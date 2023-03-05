import logging
import typing
from argparse import ArgumentParser, RawTextHelpFormatter
from logging import DEBUG
from pathlib import Path

from clang.cindex import Index, Cursor, CursorKind, TypeKind, Type, TranslationUnitLoadError
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
else:
    import ghidra_bridge

    b = ghidra_bridge.GhidraBridge(namespace=globals(), hook_import=True)

from ghidra.program.model.data import StructureDataType, DataType, CategoryPath, DataTypeConflictHandler, Category, \
    CharDataType
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl

THISCALL = "__thiscall"

logger = logging.getLogger(__name__)


class GhidraTransaction:
    def __enter__(self):
        start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logging.debug(f"Caught {exc_type} during transaction. Aborting. ({exc_val})")
            end(False)
        else:
            end(True)


STRUCTS = {}


def find_data_types(type_str):
    candidates = []
    currentProgram.getDataTypeManager().findDataTypes(type_str, candidates)
    return candidates


find_data_types = b.remoteify(find_data_types)


def parse_instance_variable(var_cursor: Cursor, category: Category) -> tuple[str, typing.Optional[DataType], bool, str]:
    var_name = var_cursor.displayname

    # children = list(field_cursor.get_children())
    # if len(children) != 1:
    #     logger.debug(f"TODO: Handle field declarations with {len(children)} children")
    #     return
    #
    # field_cursor: Cursor = next(children)
    # var_name = field_cursor.displayname

    type_name: str = var_cursor.type.spelling
    field_type: DataType | None = None
    pointer = False

    match typing.cast(Type, var_cursor.type).kind:
        case TypeKind.OBJCOBJECTPOINTER:
            pointer = True

            # Unpointered name
            type_name = typing.cast(Cursor, next(var_cursor.get_children())).displayname
            logger.debug(f"- Pointer to {type_name}")

            field_type = category.getDataType(type_name)

            if var_name == "":
                logger.error(f"- Missing pointer variable name (possible libclang issue). Returning placeholder")
                logger.error(
                    f"- {var_cursor.location.file.name}:{var_cursor.location.line}:{var_cursor.location.column}"
                )

                var_name = f"MISSING_PTR_NAME_{var_cursor.hash}"

        case TypeKind.CHAR_S:
            field_type = CharDataType()

        case other:
            # https://nshipster.com/type-encodings/

            if var_cursor.objc_type_encoding == "@":
                # Type is an object (or pointer to)
                type_candidates = find_data_types(type_name)
            else:
                # Type is primitive
                type_candidates = find_data_types(other.name.lower())

            if len(type_candidates) == 1:
                field_type = type_candidates[0]
            else:
                logger.debug(f"- TODO: Support field kind {other}")
                logger.debug(f"- Got {len(type_candidates)} type candidates for type name {var_cursor.type.spelling}")

    return type_name, field_type, pointer, var_name


def parse_interface(cursor: Cursor, category: Category, skip_fields=False, skip_methods=False):
    instance_var_cursor: Cursor
    for instance_var_cursor in cursor.get_children():
        match instance_var_cursor.kind:
            case CursorKind.OBJC_IVAR_DECL:
                if skip_fields:
                    logger.debug(f"Skipping var {instance_var_cursor.displayname}")
                    continue

                type_name, field_type, pointer, field_name = parse_instance_variable(instance_var_cursor, category)

                logger.debug(f"{instance_var_cursor.objc_type_encoding} - {field_name}")

                if field_type is None:
                    logger.debug(f"- Need to resolve {type_name} ({pointer=})")

            case CursorKind.OBJC_INSTANCE_METHOD_DECL:
                if skip_methods:
                    logger.debug(f"Skipping method {instance_var_cursor.displayname}")
                    continue

                logger.debug(f"{instance_var_cursor.kind} {instance_var_cursor.displayname}")

            case CursorKind.OBJC_PROPERTY_DECL:
                if skip_methods:
                    logger.debug(f"Skipping property {instance_var_cursor.displayname}")
                    continue

                # @property (retain, nonatomic) NSString* name;
                #
                # Generates below code:
                #
                # -(NSString*)name;
                # -(void)setName:(NSString*)userName;
                logger.debug(f"TODO: Implement {instance_var_cursor.kind} {instance_var_cursor.displayname}")
            case other:
                logger.warning(f"Unsupported cursor kind {other}")


def main(headers_path: Path, pack: bool, skip_fields, skip_methods):
    if headers_path.is_dir():
        iterator = tqdm(list(headers_path.iterdir()), unit="header", leave=False, desc="Processing headers")
    else:
        iterator = [headers_path]

    index = Index.create()
    for header_f in iterator:
        try:
            # https://github.com/llvm-mirror/clang/blob/release_60/include/clang/Driver/Types.def
            translation_unit = index.parse(header_f, args=(
                "-x", "objective-c-header",
                # "-objcmt-migrate-all",
            ))
        except TranslationUnitLoadError:
            logger.error(f"Couldn't parse file {header_f.name}. Skipping")
            continue

        with GhidraTransaction():
            category_path = CategoryPath(f"/{header_f.name}")
            logger.debug(f"Getting/creating category path {category_path}")
            category = dt_man.createCategory(category_path)

        for child in translation_unit.cursor.get_children():
            child: Cursor

            match child.kind:
                case CursorKind.OBJC_INTERFACE_DECL:
                    type_name = child.displayname
                    logger.info(f"Parsing {type_name}")
                    parse_interface(child, category, skip_fields, skip_methods)


if __name__ == "__main__":
    banner = r"""   ________    _     __                     
  / ____/ /_  (_)___/ /________ _           
 / / __/ __ \/ / __  / ___/ __ `/           
/ /_/ / / / / / /_/ / /  / /_/ /            
\____/_/_/_/_/\__,_/_/   \__,_/____         
      / __ \/ /_    (_)     / ____/         
     / / / / __ \  / /_____/ /              
    / /_/ / /_/ / / /_____/ /___            
    \____/_.___/_/ /      \____/ __         
           / //___/_  ____ _____/ /__  _____
          / /  / __ \/ __ `/ __  / _ \/ ___/
         / /__/ /_/ / /_/ / /_/ /  __/ /    
         \____|____/\__,_/\__,_/\___/_/     
                                            """
    print(banner)
    parser = ArgumentParser(
        description="Load Objective-C header data into Ghidra",
        formatter_class=RawTextHelpFormatter
    )
    # TODO: Support globs
    # TODO: Quiet mode
    parser.add_argument("headers_path", type=Path, help="Path to single header file or directory containing headers")
    parser.add_argument(
        "--disable-packing",
        dest="pack",
        action="store_false",
        default="True",
        help="Disable struct packing (Default: Enabled)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        dest="verbose",
        help="Enable verbose logging (Default: Disabled)"
    )
    parser.add_argument(
        "--skip-fields",
        action="store_true",
        default=False,
        help="Enable skipping of class field parsing (Default: Disabled)"
    )
    parser.add_argument(
        "--skip-methods",
        action="store_true",
        default=False,
        help="Enable skipping of class method parsing (Default: Disabled)"
    )

    args = parser.parse_args().__dict__

    if args.pop("verbose"):
        logger.setLevel(DEBUG)

    prog = getCurrentProgram()
    sym_table = prog.getSymbolTable()
    dt_man = prog.getDataTypeManager()
    func_man = prog.getFunctionManager()
    func_tag_man = func_man.getFunctionTagManager()

    with logging_redirect_tqdm():
        main(**args)
