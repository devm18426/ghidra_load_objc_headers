from __future__ import annotations

import faulthandler
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
    UnsignedShortDataType, LongDataType, UnsignedLongDataType, LongLongDataType, ArrayDataType, UnsignedCharDataType
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl

THISCALL = "__thiscall"

logger = logging.getLogger(__name__)


class GhidraTransaction:
    def __enter__(self):
        start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logger.debug(f"Caught {exc_type} during transaction. Aborting. ({exc_val})")
            end(False)
        else:
            end(True)


STRUCTS: dict[str, dict] = {}


def normalize_data_type_name(type_str):
    type_str = type_str.removeprefix("const ")
    type_str = type_str.removeprefix("_Atomic(").removesuffix(")")
    type_str = type_str.removeprefix("struct ")

    if type_str == "unsigned":
        type_str = "unsigned int"

    if type_str == "id":
        type_str = "ID"

    return type_str


def remote_find_data_types(type_str):
    candidates = []
    currentProgram.getDataTypeManager().findDataTypes(type_str, candidates)
    return candidates


remote_find_data_types = b.remoteify(remote_find_data_types)


def find_data_type(type_str) -> tuple[str, DataType | None]:
    """
    Search Ghidra for data type that corresponds to type_str.
    :param type_str: Name of type
    :return: Normalized name of type and type object if found, else None
    """
    type_str = normalize_data_type_name(type_str)
    type_candidates = remote_find_data_types(type_str)

    if len(type_candidates) == 1:
        return type_str, type_candidates[0]

    for candidate in type_candidates:
        if candidate.sourceArchive.archiveType == ArchiveType.BUILT_IN:
            return type_str, candidate

    return type_str, None


def parse_pointer(pointer_type: Type) -> tuple[Type | None, str, int]:
    """
    Parses a pointer data type object and extracts the pointee data type. Pointer level is also returned for cases of
    a pointer pointer.
    :param pointer_type: libclang Type object that represents a pointer
    :return: Tuple of pointer clang data type (can be None if pointee cannot be resolved), pointee data type name and
        pointer level
    """
    level = 1
    pointer_kind = pointer_type.kind
    pointee = pointer_type
    pointee_type_name = pointee.spelling
    try:
        while (pointee := pointee.get_pointee()).kind == pointer_kind:
            level += 1

    except ValueError as e:
        # TODO: Probably caused by protocol type
        logger.warning(f"Couldn't resolve pointee kind: {e} (possible libclang issue). "
                       f"Assuming pointee is not a pointer")

        match = re.match(r"(?P<type_name>.+?)<(?P<protocols>.+?)>", pointee_type_name)
        if match is not None:
            match = match.groupdict()
            pointee_type_name = match.get("type_name")
            protocols = match.get("protocols").split(", ")
            if pointee_type_name == "id" and len(protocols) == 1:
                pointee = None
                pointee_type_name = protocols[0]

    return pointee, pointee_type_name, level


def clang_to_ghidra_type(data_type: Type, var_cursor: Cursor = None) -> tuple[str, DataType | None, int]:
    variable_type: DataType | None
    type_name: str = data_type.spelling
    pointer_level = 0

    try:
        data_type.kind
    except ValueError as e:
        # TODO: Probably caused by protocol type

        logger.warning(f"- Could not process data type kind: {e} (possible libclang issue)")

        match = re.match(r"(?P<type_name>.+?)<(?P<protocols>.+?)>", data_type.spelling)
        if match is not None:
            match = match.groupdict()
            type_name = match.get("type_name")

            if type_name == "id" and (protocols := match.get("protocols")):
                protocols = protocols.split(", ")

                if len(protocols) == 1:
                    type_name = protocols[0]
        else:
            logger.warning(f"- Could not parse type name ({data_type.spelling}) and protocols using RegEx")

        type_name, variable_type = find_data_type(type_name)
        return type_name, variable_type, 0

    match data_type.kind:
        case TypeKind.OBJCOBJECTPOINTER:
            pointee_type, pointee_type_name, pointer_level = parse_pointer(data_type)

            if pointee_type is not None:
                type_name, variable_type, _ = clang_to_ghidra_type(pointee_type)
            else:
                type_name, variable_type = find_data_type(pointee_type_name)

            if variable_type is not None:
                for i in range(pointer_level):
                    variable_type = dt_man.getPointer(variable_type)
            else:
                logger.debug(f"- Could not resolve OBJC pointer type {type_name}")

        case TypeKind.CHAR_S:
            variable_type = CharDataType()

        case TypeKind.UCHAR:
            variable_type = UnsignedCharDataType()

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
            element_type_name, ghidra_element_type, _ = clang_to_ghidra_type(element_type)  # TODO: Array of pointers?

            variable_type = ArrayDataType(
                ghidra_element_type,
                data_type.element_count,
                element_type.get_size()
            )

        case TypeKind.ATOMIC:
            type_name = normalize_data_type_name(type_name)

            type_name, variable_type = find_data_type(type_name)
            if variable_type is None:
                logger.warning(f"- Failed to resolve atomic data type {type_name}")

        case TypeKind.POINTER:
            variable_type = None
            pointee_type, pointee_type_name, pointer_level = parse_pointer(data_type)

            if "unnamed struct" in type_name:
                # libclang can't parse this struct properly for some reason, parse manually
                struct_decl_tokens = var_cursor.get_tokens()

                if (struct_keyword := next(struct_decl_tokens, None)) and struct_keyword.kind == TokenKind.KEYWORD and \
                        struct_keyword.spelling == "struct":

                    if (id_token := next(struct_decl_tokens, None)) and id_token.kind == TokenKind.IDENTIFIER:
                        type_name = id_token.spelling
                        pointee_type_name, variable_type = find_data_type(type_name)

                        pointer_level = 0
                        for token in struct_decl_tokens:
                            if token.kind == TokenKind.PUNCTUATION and token.spelling == "*":
                                pointer_level += 1

            else:
                if pointee_type is not None:
                    type_name, variable_type, _ = clang_to_ghidra_type(pointee_type)

            if variable_type is not None:
                for i in range(pointer_level):
                    variable_type = dt_man.getPointer(variable_type)

            else:
                logger.debug(f"- Could not resolve pointer type {type_name}")

        case TypeKind.OBJCID:
            _, variable_type = find_data_type("ID")

        case TypeKind.ELABORATED:
            # Inline struct declaration, etc.

            if "unnamed struct" in type_name:
                struct_decl_tokens = var_cursor.type.get_declaration().get_tokens()

                next(struct_decl_tokens, None)  # Should be TokenKind.KEYWORD, spelling="struct"
                id_token = next(struct_decl_tokens, None)
                if id_token and id_token.kind == TokenKind.IDENTIFIER:
                    type_name = id_token.spelling

            type_name, variable_type = find_data_type(type_name)
            if variable_type is None:
                logger.warning(f"- Failed to resolve data type {type_name}")

        case other:
            logger.debug(f"- Got unhandled type kind {other}")

            type_name, variable_type = find_data_type(type_name)
            if variable_type is None:
                logger.warning(f"- Failed to resolve data type {type_name}")

    return type_name, variable_type, pointer_level


def parse_instance_variable(var_cursor: Cursor = None) -> tuple[str, typing.Optional[DataType], str, int]:
    var_name = var_cursor.displayname

    type_name, variable_type, pointer_level = clang_to_ghidra_type(var_cursor.type, var_cursor)

    if var_name == "" and var_cursor is not None:
        # TODO: Probably related to type protocol declaration
        logger.warning(f"- Missing pointer variable name (possible libclang issue). Returning placeholder")
        logger.warning(
            f"- {var_cursor.location.file.name}:{var_cursor.location.line}:{var_cursor.location.column}"
        )

        var_name = f"MISSING_PTR_NAME_{var_cursor.hash}"

    return type_name, variable_type, var_name, pointer_level


def parse_method(methods: dict[str, dict], method_cursor: Cursor):
    method_name = method_cursor.displayname
    method = methods.setdefault(method_name, {})
    rtype_name, rtype, rtype_pointer_level = clang_to_ghidra_type(method_cursor.result_type, method_cursor)
    method["rtype"] = rtype
    method["rtype_name"] = rtype_name
    method["rtype_ptr_level"] = rtype_pointer_level
    params = method.setdefault("params", {})

    for arg in method_cursor.get_arguments():
        params[arg.displayname] = {
            "type": arg.type.spelling,
        }


def parse_struct(struct_cursor: Cursor, category: Category, pack: bool):
    struct_type_name, struct_type = find_data_type(struct_cursor.type.spelling)
    if struct_type is not None:
        # TODO: Consider parsing anyways
        logger.debug(f"- Found existing type {struct_type_name}")
        return

    if struct_type_name.startswith("(unnamed "):
        tokens = struct_cursor.get_tokens()
        next(tokens, None)  # Should be TokenKind.KEYWORD, spelling="struct"
        id_token = next(tokens, None)
        if id_token and id_token.kind == TokenKind.IDENTIFIER:
            struct_type_name = id_token.spelling

        struct_type_name, existing_type = find_data_type(struct_type_name)

        if existing_type is not None:
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
                type_name, field_type, pointer_level = clang_to_ghidra_type(child.type, child)
                if field_type is None:
                    logger.debug(f"- Need to resolve field type {type_name}")
                    dependency = dependencies.setdefault(type_name, {
                        pointer_level: [],
                    })
                    dependency[pointer_level].append(child.displayname)

                variables[child.displayname] = {
                    "type_name": type_name,
                    "type": field_type,
                }

    if pack:
        with GhidraTransaction():
            data_type.setToDefaultPacking()


def parse_interface(cursor: Cursor, category: Category, pack: bool, skip_vars=False, skip_methods=False):
    if data_type := find_data_type(cursor.displayname)[1]:
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
                type_name, variable_type, variable_name, pointer_level = parse_instance_variable(instance_cursor)

                if variable_type is None:
                    logger.debug(f"- Need to resolve {type_name}")
                    dependency = dependencies.setdefault(type_name, {
                        pointer_level: [],
                    })
                    dependency.setdefault(pointer_level, []).append(variable_name)

                variables[variable_name] = {
                    "type_name": type_name,
                    "type": variable_type,
                }

            case CursorKind.OBJC_INSTANCE_METHOD_DECL:
                if skip_methods:
                    logger.debug(f"Skipping method {instance_cursor.displayname}")
                    continue

                logger.debug(f"Parsing method {instance_cursor.displayname}")

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

            case CursorKind.OBJC_CLASS_METHOD_DECL:
                # TODO: Implement?
                pass

            case CursorKind.UNION_DECL:
                # TODO: Implement?
                pass

            case other:
                logger.warning(f"Unsupported cursor kind {other}")


def push_structs(pack, base_category, progress, skip_vars: bool, skip_methods: bool, isa: bool):
    if len(STRUCTS) == 0:
        logger.info("No structs to push")
        return

    logger.info(f"Pushing {len(STRUCTS)} structs")

    _, class_type, = find_data_type("Class")

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

            for dep, dep_info in iiterator:
                data_type = find_data_type(dep)[1]

                if data_type is None:
                    name = dep

                    logger.debug(f"- Creating empty uncategorized struct {name} while parsing {type_name}")

                    data_type = StructureDataType(uncategorized_category.getCategoryPath(), name, 0)

                for pointer_level, variables in dep_info.items():
                    pointer_type = data_type

                    for i in range(pointer_level):
                        pointer_type = dt_man.getPointer(pointer_type)

                    for variable in variables:
                        struct["vars"][variable]["type"] = pointer_type

        # Second pass: Struct population
        iterator = STRUCTS.items()
        if progress:
            iterator = tqdm(iterator, unit="struct", leave=False, desc="Pushing structs")

        for type_name, struct in iterator:
            data_type = struct["type"]

            if not skip_vars:
                data_type.deleteAll()

                iiterator = OrderedDict(reversed(list(struct["vars"].items()))).items()
                if progress:
                    iiterator = tqdm(iiterator, unit="var", leave=False, desc=f"Pushing variables ({type_name})")

                # Push variables
                for variable_name, var in iiterator:
                    data_type.insertAtOffset(0, var["type"], var["type"].length, variable_name, "")

                if pack:
                    data_type.setToDefaultPacking()

            if isa:
                data_type.insertAtOffset(0, class_type, class_type.length, "isa", "")

            if not skip_methods:
                # Push methods
                namespace = sym_table.getNamespace(type_name, None)
                if namespace is None:
                    logger.debug(f"Couldn't find symbol {type_name}. Skipping method pushing")
                    continue

                iiterator = struct.get("methods").items()
                if progress:
                    iiterator = tqdm(iiterator, leave=False, unit="method", desc=f"Pushing methods ({type_name})")

                symbols = sym_table.getSymbols(namespace.getBody(), SymbolType.FUNCTION, True)
                for symbol in symbols:
                    if method := struct.get("methods").get(symbol.name):
                        params = []

                        for param_name, param in method["params"].items():
                            _, param_type = find_data_type(param["type"])

                            if param_type is not None:
                                params.append(ParameterImpl(
                                    param_name,
                                    param_type,
                                    prog,
                                ))

                        return_type = method["rtype"]
                        if return_type is None:
                            _, return_type = find_data_type(method["rtype_name"])

                            if return_type is None:
                                logger.error(f"{type_name}::{symbol.name}")
                                logger.error(f"- Failed to resolve return data type {method['rtype_name']}")

                            else:
                                for i in range(method["rtype_ptr_level"]):
                                    return_type = dt_man.getPointer(return_type)

                        func = func_man.getFunction(symbol.getID())
                        func.updateFunction(
                            THISCALL,
                            ReturnParameterImpl(return_type, prog),
                            params,
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                            False,
                            SourceType.USER_DEFINED,
                        )

                    if progress:
                        iiterator.update()

                if progress:
                    iiterator.close()

    logger.info("Done")


def main(
        headers: Iterator,
        pack: bool,
        progress: bool,
        skip_vars: bool,
        skip_methods: bool,
        base_category: str,
        isa: bool
):
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

    push_structs(pack, base_category, progress, skip_vars, skip_methods, isa)


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
    parser.add_argument(
        "--no-isa",
        action="store_false",
        default=True,
        dest="isa",
        help="Disable adding of the isa field to parsed structs (Default: Enabled)"
    )

    args = parser.parse_args().__dict__

    faulthandler.enable()

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

    try:
        if args["progress"]:
            with logging_redirect_tqdm(loggers=[logger]):
                main(**args)

        else:
            main(**args)
    except BaseException as e:
        message = f": {e}" if str(e) else ""
        logger.error(f"Caught {type(e).__name__}{message}")
        logger.error(e, exc_info=True)
        logger.error("Quitting...")
