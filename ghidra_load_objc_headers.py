from __future__ import annotations

import logging
import re
import sys
import typing
from argparse import ArgumentParser, RawTextHelpFormatter
from collections import OrderedDict
from functools import partial
from glob import iglob
from logging import DEBUG, INFO
from pathlib import Path
from typing import Iterator

from clang.cindex import Index, Cursor, CursorKind, TypeKind, Type, TranslationUnitLoadError, TokenKind
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
else:
    import ghidra_bridge

    b = ghidra_bridge.GhidraBridge(namespace=globals(), hook_import=True)

from ghidra.program.database.data import StructureDB
from ghidra.program.model.data import StructureDataType, DataType, CategoryPath, DataTypeConflictHandler, Category, \
    CharDataType, ArchiveType, IntegerDataType, UnsignedIntegerDataType, ShortDataType, UnsignedLongLongDataType, \
    UnsignedShortDataType, LongDataType, UnsignedLongDataType, LongLongDataType, ArrayDataType
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


def remote_find_data_types(type_str):
    candidates = []
    currentProgram.getDataTypeManager().findDataTypes(type_str, candidates)
    return candidates


remote_find_data_types = b.remoteify(remote_find_data_types)


def find_data_types(type_str):
    return remote_find_data_types(type_str)


def find_data_type(type_str) -> DataType | None:
    """
    Search Ghidra for data type that corresponds to type_str.
    :param type_str: Name of type
    :return: Type if found, else None
    """
    type_candidates = find_data_types(type_str)

    if len(type_candidates) == 1:
        return type_candidates[0]

    for candidate in type_candidates:
        if candidate.sourceArchive.archiveType == ArchiveType.BUILT_IN:
            return candidate


def parse_pointer(data_type: Type, pointer_kind: TypeKind):
    level = 1
    pointee = data_type
    try:
        while (pointee := pointee.get_pointee()).kind == pointer_kind:
            level += 1

        type_name = pointee.spelling
    except ValueError as e:
        # TODO: Probably caused by protocol type
        logger.warning(f"Couldn't resolve pointee kind: {e} (possible libclang issue). "
                       f"Assuming pointee is not a pointer")

        match = re.match(r"(?P<type_name>.+?)<.+?>", pointee.spelling)
        type_name = match.groupdict().get("type_name")

    variable_type = find_data_type(type_name)
    if variable_type is not None:
        for i in range(level):
            variable_type = dt_man.getPointer(variable_type)

    return variable_type


def clang_to_ghidra_type(data_type: Type, var_cursor: Cursor = None):
    variable_type: DataType | None
    type_name: str = data_type.spelling.removeprefix("struct ")

    match data_type.kind:
        case TypeKind.OBJCOBJECTPOINTER:
            variable_type = parse_pointer(data_type, TypeKind.OBJCOBJECTPOINTER)
            if variable_type is None:
                logger.debug(f"- Could not resolve OBJC pointer type {type_name}")

        case TypeKind.CHAR_S:
            variable_type = CharDataType()

        case TypeKind.INT:
            variable_type = IntegerDataType()

        case TypeKind.UINT:
            variable_type = UnsignedIntegerDataType()

        case TypeKind.LONG:
            variable_type = LongDataType()

        case TypeKind.ULONG:
            variable_type = UnsignedLongDataType()

        case TypeKind.LONGLONG:
            variable_type = LongLongDataType()

        case TypeKind.ULONGLONG:
            variable_type = UnsignedLongLongDataType()

        case TypeKind.SHORT:
            variable_type = ShortDataType()

        case TypeKind.USHORT:
            variable_type = UnsignedShortDataType()

        case TypeKind.CONSTANTARRAY:
            element_type = data_type.get_array_element_type()
            element_type_name, ghidra_element_type = clang_to_ghidra_type(element_type)

            variable_type = ArrayDataType(
                ghidra_element_type,
                data_type.element_count,
                element_type.get_size()
            )

        case TypeKind.ATOMIC:
            atomic_tokens = var_cursor.get_tokens()

            next(atomic_tokens, None)  # Should be TokenKind.KEYWORD, spelling="_Atomic"
            id_token = next(atomic_tokens, None)
            if id_token and id_token.kind in (TokenKind.IDENTIFIER, TokenKind.KEYWORD):
                type_name = id_token.spelling

            variable_type = find_data_type(type_name)
            if variable_type is None:
                logger.error(f"- Failed to resolve atomic data type {type_name}")

        case TypeKind.POINTER:
            if "unnamed struct" in type_name:
                struct_decl_tokens = var_cursor.get_tokens()

                if (struct_keyword := next(struct_decl_tokens, None)) and struct_keyword.kind == TokenKind.KEYWORD and \
                        struct_keyword.spelling == "struct":

                    if (id_token := next(struct_decl_tokens, None)) and id_token.kind == TokenKind.IDENTIFIER:
                        type_name = id_token.spelling

            variable_type = parse_pointer(data_type, TypeKind.POINTER)
            if variable_type is None:
                logger.debug(f"- Could not resolve pointer type {type_name}")

        case TypeKind.ELABORATED:
            # Inline struct declaration, etc.

            if "unnamed struct" in type_name:
                struct_decl_tokens = var_cursor.type.get_declaration().get_tokens()

                next(struct_decl_tokens, None)  # Should be TokenKind.KEYWORD, spelling="struct"
                id_token = next(struct_decl_tokens, None)
                if id_token and id_token.kind == TokenKind.IDENTIFIER:
                    type_name = id_token.spelling

            variable_type = find_data_type(type_name)
            if variable_type is None:
                logger.error(f"- Failed to resolve data type {type_name}")

        case other:
            logger.debug(f"- Got unhandled type kind {other}")

            variable_type = find_data_type(type_name)
            if variable_type is None:
                logger.error(f"- Failed to resolve data type {type_name}")

    return type_name, variable_type


def parse_instance_variable(var_cursor: Cursor = None) ->\
        tuple[str, typing.Optional[DataType], str]:
    var_name = var_cursor.displayname

    type_name, variable_type = clang_to_ghidra_type(var_cursor.type, var_cursor)

    if var_name == "" and var_cursor is not None:
        # TODO: Probably related to type protocol declaration
        logger.error(f"- Missing pointer variable name (possible libclang issue). Returning placeholder")
        logger.error(
            f"- {var_cursor.location.file.name}:{var_cursor.location.line}:{var_cursor.location.column}"
        )

        var_name = f"MISSING_PTR_NAME_{var_cursor.hash}"

    return type_name, variable_type, var_name


def parse_method(methods: dict[str, dict], method_cursor: Cursor):
    method_name = method_cursor.displayname
    method = methods.setdefault(method_name, {})
    method["rtype"] = method_cursor.result_type.spelling
    method["rtype_pointer"] = method_cursor.result_type.kind == TypeKind.POINTER
    params = method.setdefault("params", {})

    for arg in method_cursor.get_arguments():
        params[arg.displayname] = {
            "type": arg.type.spelling,
        }

    pass
    # children: list[Cursor] = list(method_cursor.get_children())
    # for child in children:
    #     match child.kind:
    #         case CursorKind.OBJC_PROTOCOL_REF:
    #             # TODO: Figure this out
    #             pass
    #
    #         case other:
    #             logger.debug(f"- Unhandled cursor kind {child.kind} (method {method_name})")


def parse_struct(struct_cursor: Cursor, category: Category, pack: bool):
    struct_type_name = struct_cursor.type.spelling.removeprefix("struct ")

    candidates = find_data_types(struct_type_name)

    if len(candidates) == 1:
        # TODO: Consider parsing anyways
        logger.debug(f"- Found existing type {struct_type_name}")
        return

    else:
        if struct_type_name.startswith("(unnamed "):
            tokens = struct_cursor.get_tokens()
            next(tokens, None)  # Should be TokenKind.KEYWORD, spelling="struct"
            id_token = next(tokens, None)
            if id_token and id_token.kind == TokenKind.IDENTIFIER:
                struct_type_name = id_token.spelling

            candidates = find_data_types(struct_type_name)

            if len(candidates) == 1:
                logger.debug(f"- Found existing type {struct_type_name}")
                return

        with GhidraTransaction():
            data_type = StructureDataType(category.getCategoryPath(), struct_type_name, 0)

            logger.debug(f"- Pushing {struct_type_name} to {category}")

            data_type = category.addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)

    struct = STRUCTS.setdefault(struct_type_name, {})
    variables = struct.setdefault("vars", OrderedDict())
    struct.setdefault("methods", {})
    dependencies = struct.setdefault("deps", {})
    struct["type"] = data_type

    for child in struct_cursor.get_children():
        match child.kind:
            case CursorKind.FIELD_DECL:
                field_type = None
                pointer = False

                field_type_candidates = find_data_types(child.type.spelling)
                if len(field_type_candidates) == 1:
                    field_type = field_type_candidates[0]

                else:
                    for candidate in field_type_candidates:
                        if candidate.sourceArchive.archiveType == ArchiveType.BUILT_IN:
                            field_type = candidate
                            break

                    if field_type is None:
                        logger.debug(f"- Need to resolve field type {child.type.spelling} ({pointer=})")
                        dependency = dependencies.setdefault(child.type.spelling, [])
                        dependency.append(child.displayname)

                variables[child.displayname] = {
                    "type_name": child.type.spelling,
                    "type": field_type,
                    "pointer": pointer,
                }

    if pack:
        with GhidraTransaction():
            data_type.setToDefaultPacking()


def parse_interface(cursor: Cursor, category: Category, pack: bool, skip_vars=False, skip_methods=False):
    if data_type := find_data_type(cursor.displayname):
        logger.debug(f"- Found existing type {cursor.displayname}")

        if not isinstance(data_type, StructureDB):
            logger.debug(f"- Existing type is {data_type}, skipping")
            return

    else:
        with GhidraTransaction():
            data_type = StructureDataType(category.getCategoryPath(), cursor.displayname, 0)

            logger.debug(f"- Pushing {cursor.displayname} to {category}")
            data_type = category.addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)

    struct = STRUCTS.setdefault(cursor.displayname, {})
    variables = struct.setdefault("vars", OrderedDict())
    methods = struct.setdefault("methods", {})
    dependencies = struct.setdefault("deps", {})

    struct["type"] = data_type

    instance_cursor: Cursor
    for instance_cursor in cursor.get_children():
        match instance_cursor.kind:
            case CursorKind.OBJC_IVAR_DECL:
                if skip_vars:
                    logger.debug(f"Skipping var {instance_cursor.displayname}")
                    continue

                logger.debug(f"Parsing var {instance_cursor.displayname}")
                type_name, variable_type, variable_name = \
                    parse_instance_variable(instance_cursor)

                # logger.debug(f"{instance_cursor.objc_type_encoding} - {variable_name}")

                if variable_type is None:
                    logger.debug(f"- Need to resolve {type_name}")
                    dependency = dependencies.setdefault(type_name, [])
                    dependency.append(variable_name)

                variables[variable_name] = {
                    "type_name": type_name,
                    "type": variable_type,
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

            case CursorKind.STRUCT_DECL:
                parse_struct(instance_cursor, category, pack)

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
                data_type: StructureDataType | None = None
                type_candidates = find_data_types(dep)

                if (candidates := len(type_candidates)) == 0:
                    logger.debug(f"- Creating empty uncategorized struct {dep} while parsing {type_name}")

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
            data_type = struct["type"]

            data_type.deleteAll()

            iiterator = OrderedDict(reversed(list(struct["vars"].items()))).items()
            if progress:
                iiterator = tqdm(iiterator, unit="var", leave=False, desc=f"Pushing variables ({type_name})")

            # Push variables
            for variable_name, var in iiterator:
                data_type.insertAtOffset(0, var["type"], var["type"].length, variable_name, "")

            if pack:
                data_type.setToDefaultPacking()

            # Push methods
            namespace = sym_table.getNamespace(type_name, None)
            if namespace is None:
                logger.debug(f"Couldn't find symbol {type_name}. Skipping method pushing")
                continue

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
                    logger.info(f"Parsing interface {type_name}")
                    parse_interface(child, category, pack, skip_vars=skip_vars, skip_methods=skip_methods)

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
        action="count",
        default=0,
        dest="verbosity",
        help="Set logging verbosity (Default: Least verbosity)",
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
    handler.setFormatter(logging.Formatter("[%(levelname)-7s] %(message)s"))

    verbosity = args.pop("verbosity")
    if verbosity > 0:
        logger.setLevel(DEBUG)

        if verbosity == 1:
            handler.setFormatter(logging.Formatter("[%(levelname)-7s][%(filename)s:%(lineno)d] %(message)s"))

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
