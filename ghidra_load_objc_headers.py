import logging
import sys
import typing
from argparse import ArgumentParser, RawTextHelpFormatter
from collections import OrderedDict
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


STRUCTS: dict[str, dict] = {}


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
    variable_type: DataType | None = None
    pointer = False

    match typing.cast(Type, var_cursor.type).kind:
        case TypeKind.OBJCOBJECTPOINTER:
            pointer = True

            # Unpointered name
            type_name = typing.cast(Cursor, next(var_cursor.get_children())).displayname
            logger.debug(f"- Pointer to {type_name}")

            variable_type = category.getDataType(type_name)

            if var_name == "":
                logger.error(f"- Missing pointer variable name (possible libclang issue). Returning placeholder")
                logger.error(
                    f"- {var_cursor.location.file.name}:{var_cursor.location.line}:{var_cursor.location.column}"
                )

                var_name = f"MISSING_PTR_NAME_{var_cursor.hash}"

            if variable_type is None:
                logger.debug(f"- Creating empty struct {type_name}")

        case TypeKind.CHAR_S:
            variable_type = CharDataType()

        case other:
            # https://nshipster.com/type-encodings/

            if var_cursor.objc_type_encoding == "@":
                # Type is an object (or pointer to)
                type_candidates = find_data_types(type_name)
            else:
                # Type is primitive
                type_candidates = find_data_types(other.name.lower())

            if len(type_candidates) == 1:
                variable_type = type_candidates[0]
            else:
                logger.debug(f"- TODO: Support variable kind {other}")
                logger.debug(f"- Got {len(type_candidates)} type candidates for type name {var_cursor.type.spelling}")

    return type_name, variable_type, pointer, var_name


def parse_interface(cursor: Cursor, category: Category, skip_fields=False, skip_methods=False):
    struct = STRUCTS.setdefault(cursor.displayname, {})
    variables = struct.setdefault("vars", OrderedDict())
    methods = struct.setdefault("methods", [])
    dependencies = struct.setdefault("deps", {})

    with GhidraTransaction():
        data_type = StructureDataType(category.getCategoryPath(), cursor.displayname, 0)
        logger.debug(f"- Pushing {cursor.displayname} to {category}")
        data_type = category.addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)

        struct["type"] = data_type

    instance_var_cursor: Cursor
    for instance_var_cursor in cursor.get_children():
        match instance_var_cursor.kind:
            case CursorKind.OBJC_IVAR_DECL:
                if skip_fields:
                    logger.debug(f"Skipping var {instance_var_cursor.displayname}")
                    continue

                type_name, variable_type, pointer, variable_name =\
                    parse_instance_variable(instance_var_cursor, category)

                logger.debug(f"{instance_var_cursor.objc_type_encoding} - {variable_name}")

                if variable_type is None:
                    logger.debug(f"- Need to resolve {type_name} ({pointer=})")
                    dependency = dependencies.setdefault(type_name, [])
                    dependency.append(variable_name)

                variables[variable_name] = {
                    "type_name": type_name,
                    "type": variable_type,
                    "pointer": pointer,
                }

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


def push_structs(base_category):
    if len(STRUCTS) == 0:
        logger.info("No structs to push")
        return

    logger.info(f"Pushing {len(STRUCTS)} structs")
    logger.debug(f"{STRUCTS=}")

    with GhidraTransaction():
        # Unknown types should go in an "uncategorized" category
        category_path = CategoryPath(f"/{base_category}/___MISSING_TYPES")
        logger.debug(f"Getting/creating category path {category_path}")
        uncategorized_category = dt_man.createCategory(category_path)

        # Resolve dependencies
        for type_name, struct in tqdm(STRUCTS.items(), leave=False, unit="struct", desc="Resolving dependencies"):
            for dep, variables in tqdm(struct.get("deps").items(), leave=False, unit="dep", desc=f"Processing {type_name}"):
                type_candidates = find_data_types(dep)

                if (candidates := len(type_candidates)) == 0:
                    logger.debug(f"- Creating empty uncategorized struct {dep}")

                    data_type = StructureDataType(uncategorized_category.getCategoryPath(), dep, 0)

                elif candidates == 1:
                    data_type = type_candidates[0]

                elif candidates != 1:
                    logger.debug(f"- Got {candidates} type candidates for dependency type name {dep}")
                    continue

                for variable in variables:
                    struct["vars"][variable]["type"] = data_type

        # Populate structs
        for type_name, struct in tqdm(STRUCTS.items(), unit="struct", leave=False, desc="Pushing structs"):
            data_type = struct["type"]

            for variable_name, var in tqdm(OrderedDict(reversed(list(struct["vars"].items()))).items(), unit="var", leave=False):
                if var["pointer"]:
                    pointer = dt_man.getPointer(var["type"])
                    data_type.insertAtOffset(0, pointer, pointer.length, variable_name, "")
                else:
                    data_type.insertAtOffset(0, var["type"], var["type"].length, variable_name, "")


def main(headers_path: Path, pack: bool, skip_fields, skip_methods, base_category):
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
            category_path = CategoryPath(f"/{base_category}/{header_f.name}")
            logger.debug(f"Getting/creating category path {category_path}")
            category = dt_man.createCategory(category_path)

        for child in translation_unit.cursor.get_children():
            child: Cursor

            match child.kind:
                case CursorKind.OBJC_INTERFACE_DECL:
                    type_name = child.displayname
                    logger.info(f"Parsing {type_name}")
                    parse_interface(child, category, skip_fields, skip_methods)

    push_structs(base_category)


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
    parser.add_argument(
        "-c", "--base-category",
        default=(default := "objc_loader"),
        dest="base_category",
        help=f"Base category path for all loaded types (Default: {default})",
    )

    args = parser.parse_args().__dict__

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))

    if args.pop("verbose"):
        logger.setLevel(DEBUG)
        handler.setFormatter(logging.Formatter("[%(levelname)-5s] %(message)s"))

    logger.addHandler(handler)
    logger.propagate = False

    prog = getCurrentProgram()
    sym_table = prog.getSymbolTable()
    dt_man = prog.getDataTypeManager()
    func_man = prog.getFunctionManager()
    func_tag_man = func_man.getFunctionTagManager()

    with logging_redirect_tqdm(loggers=[logger]):
        main(**args)
