import logging
import sys
import typing
from argparse import ArgumentParser, RawTextHelpFormatter
from collections import OrderedDict
from functools import partial
from glob import iglob
from pathlib import Path
from typing import Iterator

from clang.cindex import Index, Cursor, CursorKind, TypeKind, Type, TranslationUnitLoadError
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
else:
    import ghidra_bridge

    b = ghidra_bridge.GhidraBridge(namespace=globals(), hook_import=True)

from ghidra.program.model.data import StructureDataType, DataType, CategoryPath, DataTypeConflictHandler, Category, \
    CharDataType, ArchiveType
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


def parse_method(methods: dict[str, dict], method_cursor: Cursor):
    method_name = method_cursor.displayname
    method = methods.setdefault(method_name, {})
    method["rtype"] = None
    method["rtype_pointer"] = None
    params = method.setdefault("params", {})

    match method_cursor.objc_type_encoding[0]:
        case "@":
            method["rtype_pointer"] = True
        case "v":
            method["rtype"] = "void"
        case "c":
            method["rtype"] = "char"
        case "i":
            method["rtype"] = "int"
        case "s":
            method["rtype"] = "short"
        case "q":
            method["rtype"] = "long long"
        case "C":
            method["rtype"] = "unsigned char"
        case "I":
            method["rtype"] = "unsigned int"
        case "S":
            method["rtype"] = "unsigned short"
        case "L":
            method["rtype"] = "unsigned long"
        case "Q":
            method["rtype"] = "unsigned long long"
        case "f":
            method["rtype"] = "float"
        case "d":
            method["rtype"] = "double"
        case "B":
            method["rtype"] = "bool"
        case other:
            logger.debug(f"- Unrecognized return type encoding {other} (method {method_name})")

    children: list[Cursor] = list(method_cursor.get_children())
    for child in children:
        match child.kind:
            case CursorKind.PARM_DECL:
                param = params.setdefault(child.displayname, {})
                param["type"] = child.type.spelling

            case CursorKind.OBJC_CLASS_REF:
                method["rtype"] = child.displayname

            case CursorKind.TYPE_REF:
                method["rtype"] = child.displayname

            case CursorKind.OBJC_PROTOCOL_REF:
                # TODO: Figure this out
                pass

            case other:
                logger.debug(f"- Unhandled cursor kind {child.kind} (method {method_name})")


def parse_interface(cursor: Cursor, category: Category, skip_vars=False, skip_methods=False):
    struct = STRUCTS.setdefault(cursor.displayname, {})
    variables = struct.setdefault("vars", OrderedDict())
    methods = struct.setdefault("methods", {})
    dependencies = struct.setdefault("deps", {})

    with GhidraTransaction():
        data_type = StructureDataType(category.getCategoryPath(), cursor.displayname, 0)

        logger.debug(f"- Pushing {cursor.displayname} to {category}")
        data_type = category.addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)

        struct["type"] = data_type

    instance_cursor: Cursor
    for instance_cursor in cursor.get_children():
        match instance_cursor.kind:
            case CursorKind.OBJC_IVAR_DECL:
                if skip_vars:
                    logger.debug(f"Skipping var {instance_cursor.displayname}")
                    continue

                type_name, variable_type, pointer, variable_name = \
                    parse_instance_variable(instance_cursor, category)

                logger.debug(f"{instance_cursor.objc_type_encoding} - {variable_name}")

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
                    logger.debug(f"Skipping method {instance_cursor.displayname}")
                    continue

                logger.debug(f"{instance_cursor.kind} {instance_cursor.displayname}")

                parse_method(methods, instance_cursor)

            case CursorKind.OBJC_PROPERTY_DECL:
                if skip_methods:
                    logger.debug(f"Skipping property {instance_cursor.displayname}")
                    continue

                # @property (retain, nonatomic) NSString* name;
                #
                # Generates below code:
                #
                # -(NSString*)name;
                # -(void)setName:(NSString*)userName;
                logger.debug(f"TODO: Implement {instance_cursor.kind} {instance_cursor.displayname}")
            case other:
                logger.warning(f"Unsupported cursor kind {other}")


def push_structs(pack, base_category, progress):
    if len(STRUCTS) == 0:
        logger.info("No structs to push")
        return

    logger.info(f"Pushing {len(STRUCTS)} structs")

    with GhidraTransaction():
        # Unknown types should go in an "uncategorized" category
        category_path = CategoryPath(f"/{base_category}/___MISSING_TYPES")
        logger.debug(f"Getting/creating category path {category_path}")
        uncategorized_category = dt_man.createCategory(category_path)

        # First pass: Dependency resolution
        iterator = STRUCTS.items()
        if progress:
            iterator = tqdm(iterator, leave=False, unit="struct", desc="Resolving dependencies")

        for type_name, struct in iterator:
            iiterator = struct.get("deps").items()
            if progress:
                iiterator = tqdm(iiterator, leave=False, unit="dep", desc=f"Processing {type_name}")

            for dep, variables in iiterator:
                type_candidates = find_data_types(dep)

                if (candidates := len(type_candidates)) == 0:
                    logger.debug(f"- Creating empty uncategorized struct {dep}")

                    data_type = StructureDataType(uncategorized_category.getCategoryPath(), dep, 0)

                elif candidates == 1:
                    data_type = type_candidates[0]

                else:
                    for candidate in type_candidates:
                        if candidate.sourceArchive.archiveType == ArchiveType.BUILT_IN:
                            data_type = candidate
                            break

                    if data_type is None:
                        logger.error(f"- Failed to resolve data type {dep}")

                for variable in variables:
                    struct["vars"][variable]["type"] = data_type

        # Second pass: Struct population
        iterator = STRUCTS.items()
        if progress:
            iterator = tqdm(iterator, unit="struct", leave=False, desc="Pushing structs")

        for type_name, struct in iterator:
            data_type: StructureDataType = struct["type"]

            data_type.deleteAll()

            iiterator = OrderedDict(reversed(list(struct["vars"].items()))).items()
            if progress:
                iiterator = tqdm(iiterator, unit="var", leave=False, desc=f"Pushing variables ({type_name})")

            # Push variables
            for variable_name, var in iiterator:
                if var["pointer"]:
                    pointer = dt_man.getPointer(var["type"])
                    data_type.insertAtOffset(0, pointer, pointer.length, variable_name, "")
                else:
                    data_type.insertAtOffset(0, var["type"], var["type"].length, variable_name, "")

            if pack:
                data_type.setToDefaultPacking()

            # Push methods
            namespace = sym_table.getNamespace(type_name, None)
            iiterator = struct.get("methods").items()
            if progress:
                iiterator = tqdm(iiterator, leave=False, unit="method", desc=f"Pushing methods ({type_name})")

            symbols = sym_table.getSymbols(namespace)
            # TODO: Speed this up
            symbols = {
                symbol.getName(): symbol
                for symbol in filter(lambda symbol: symbol.getSymbolType() == SymbolType.FUNCTION, symbols)
            }

            for method_name, method in iiterator:

                if symbol := symbols.get(method_name):
                    params = []

                    for param_name, param in method["params"].items():
                        param_type_candidates = find_data_types(param["type"])

                        if len(param_type_candidates) == 1:
                            params.append(ParameterImpl(
                                param_name,
                                param_type_candidates[0],
                                prog,
                            ))

                    return_type_candidates = find_data_types(method["rtype"])
                    return_type = None
                    if len(return_type_candidates) == 1:
                        return_type = return_type_candidates[0]

                        if method["rtype_pointer"]:
                            return_type = dt_man.getPointer(return_type)
                    else:
                        for candidate in return_type_candidates:
                            if candidate.sourceArchive.archiveType == ArchiveType.BUILT_IN:
                                return_type = candidate
                                break

                        if return_type is None:
                            logger.error(f"- Failed to resolve return data type {method['rtype']}")

                    func = func_man.getFunction(symbol.getID())
                    func.updateFunction(
                        THISCALL,
                        ReturnParameterImpl(return_type, prog),
                        params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        False,
                        SourceType.USER_DEFINED,
                    )

    logger.info("Done")


def main(headers: Iterator, pack: bool, progress: bool, skip_vars: bool, skip_methods: bool, base_category: str):
    iterator = list(headers)

    if len(iterator) == 0:
        logger.info("No files to parse")
        return

    if progress:
        iterator = tqdm(iterator, unit="header", leave=False, desc="Parsing headers")

    index = Index.create()
    for header in iterator:
        header_f = Path(header)

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
                    parse_interface(child, category, skip_vars, skip_methods)

    push_structs(pack, base_category, progress)


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
    parser.add_argument("headers", type=partial(iglob, recursive=True), help="Path to header files (globs supported)")
    parser.add_argument(
        "--disable-packing",
        dest="pack",
        action="store_false",
        default=True,
        help="Disable struct packing (Default: Enabled)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        dest="verbose",
        help="Enable verbose logging (Default: Disabled)",
    )
    parser.add_argument(
        "--no-prog",
        action="store_false",
        dest="progress",
        default=True,
        help="Disable progress bars (Default: Enabled)",
    )
    parser.add_argument(
        "--skip-vars",
        action="store_true",
        default=False,
        help="Enable skipping of instance variable parsing (Default: Disabled)",
    )
    parser.add_argument(
        "--skip-methods",
        action="store_true",
        default=False,
        help="Enable skipping of class method parsing (Default: Disabled)",
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
    else:
        logger.setLevel(INFO)

    logger.addHandler(handler)
    logger.propagate = False

    prog = getCurrentProgram()
    sym_table = prog.getSymbolTable()
    dt_man = prog.getDataTypeManager()
    func_man = prog.getFunctionManager()
    func_tag_man = func_man.getFunctionTagManager()

    if args["progress"]:
        with logging_redirect_tqdm(loggers=[logger]):
            main(**args)

    else:
        main(**args)
