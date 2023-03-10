import re
import typing
from argparse import ArgumentParser, RawTextHelpFormatter
from pathlib import Path
from typing import Optional

from tqdm import tqdm

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
else:
    import ghidra_bridge

    b = ghidra_bridge.GhidraBridge(namespace=globals(), hook_import=True)

from ghidra.program.model.data import StructureDataType, DataType, CategoryPath, DataTypeConflictHandler
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl

# TODO: Consider using libclang AST instead of regexes...
# https://libclang.readthedocs.io/en/latest/
TYPE_REGEX_TEMPLATE = r"(?P<{type}>.+?(\s+\*)?)(<(?P<{protocols}>.+?)>)?"

INTERFACE_REGEX = re.compile(
    r"@interface (?P<name>[a-zA-Z]+).+?\{(?P<data>.+?)\n\}",
    re.DOTALL
)

# '(?P<type>.+?(\\s+\\*)?)(<(?P<protocols>.+?)>)?$'
TYPE_REGEX = re.compile(TYPE_REGEX_TEMPLATE.format(type="type", protocols="protocols") + "$", re.MULTILINE)

# '-\\((?P<rtype>.+?(\\s+\\*)?)(<(?P<rprotocols>.+?)>)?\\)(?P<name>\\S+?)(;|(:\\((?P<arg1_type>.+?(\\s+\\*)?)(<(?P<arg1_protocols>.+?)>)?\\)arg1\\s+?((?P<args>.+?)\\s?)?);)'
METHOD_REGEX = re.compile(
    f"-\\({TYPE_REGEX_TEMPLATE.format(type='rtype', protocols='rprotocols')}\\)(?P<name>\\S+?)(;|(:\\({TYPE_REGEX_TEMPLATE.format(type='arg1_type', protocols='arg1_protocols')}\\)arg1\\s+?((?P<args>.+?)\\s?)?);)",
    re.MULTILINE
)

# '(?P<name>\\S+):\\((?P<type>.+?(\\s+\\*)?)(<(?P<protocols>.+?)>)?\\)arg[0-9]+'
ARGS_REGEX = re.compile(
    f"(?P<name>\\S+):\\({TYPE_REGEX_TEMPLATE.format(type='type', protocols='protocols')}\\)arg[0-9]+",
    re.DOTALL
)

THISCALL = "__thiscall"


# TODO: https://github.com/justfoxing/jfx_bridge/issues/19
def findDataTypes(type_str):
    candidates = []
    currentProgram.getDataTypeManager().findDataTypes(type_str, candidates)
    return candidates


findDataTypes = b.remoteify(findDataTypes)


def resolve_data_type(type_name, field_name=None) -> Optional[DataType]:
    if "^block" in type_name:
        # TODO: Consider implementing full Block_literal struct
        # https://www.cocoawithlove.com/2009/10/how-blocks-are-implemented-and.html
        # struct Block_literal {
        #     void *isa;
        #
        #     int flags;
        #     int reserved; // is actually the retain count of heap allocated blocks
        #
        #     void (*invoke)(void *, ...); // a pointer to the block's compiled code
        #
        #     struct Block_descriptor {
        #         unsigned long int reserved; // always nil
        #         unsigned long int size; // size of the entire Block_literal
        #
        #         // functions used to copy and dispose of the block (if needed)
        #         void (*copy_helper)(void *dst, void *src);
        #         void (*dispose_helper)(void *src);
        #     } *descriptor;
        #
        #     // Here the struct contains one entry for every surrounding scope variable.
        #     // For non-pointers, these entries are the actual const values of the variables.
        #     // For pointers, there are a range of possibilities (__block pointer,
        #     // object pointer, weak pointer, ordinary pointer)
        # };
        type_name = "Block_literal *"

    # Remove protocols
    # TODO: Consider adding an option that preserves protocols
    type_name = re.match(TYPE_REGEX, type_name)["type"]

    pointer = False
    if type_name.endswith("*"):
        pointer = True

        type_name = type_name.rstrip("* ")

    type_name = type_name.removeprefix("const ")

    candidates = findDataTypes(type_name)

    data_type = None
    if len(candidates) > 0:
        data_type = candidates[0]

    if data_type is None and type_name == "unsigned":
        return resolve_data_type("unsigned int", field_name)

    if data_type is None:
        tqdm.write(f"- Unknown data type {type_name}" +
                   (" *" if pointer else "") +
                   (f" (field {field_name})" if field_name is not None else ""))

        if pointer:
            tqdm.write("- Pointer detected. Creating empty struct")
            data_type = StructureDataType(type_name, 0)
            dt_man.addDataType(data_type, None)

        else:
            tqdm.write("- Skipping. This will probably ruin your struct")

    if data_type and pointer:
        data_type = dt_man.getPointer(data_type)

    return data_type


def load_struct_fields(struct, category, fields):
    start()

    category.addDataType(struct, DataTypeConflictHandler.KEEP_HANDLER)

    struct.deleteAll()

    for field in tqdm(fields, unit="field", desc="Loading structs", leave=False):
        split = field.rsplit(maxsplit=1)
        if len(split) != 2:
            tqdm.write(f" - Encountered field with no type specified ({split}). Skipping")
            continue

        type_name, field_name = split

        data_type = resolve_data_type(type_name, field_name)
        if data_type is None:
            continue

        struct.insertAtOffset(0, data_type, data_type.length, field_name, None)

    end(True)


def update_method(class_name, methods):
    tqdm.write(f"- Getting class symbol {class_name}")

    namespace = sym_table.getNamespace(class_name, None)
    if namespace is None:
        tqdm.write(f"- Couldn't find class symbol {class_name}")
        return

    symbols = getCurrentProgram().getSymbolTable().getSymbols(namespace)
    symbols = {
        symbol.getName(): symbol
        for symbol in filter(lambda symbol: symbol.getSymbolType() == SymbolType.FUNCTION, symbols)
    }

    start()
    for method in tqdm(methods, unit="method", leave=False, desc="Updating methods"):
        name = method["name"]
        params = []

        if method["arg1_type"]:
            name += ":"

        if method["args"]:
            args = list(re.finditer(ARGS_REGEX, method["args"]))
            name += ":".join([arg["name"] for arg in args]) + ":"

            params = []
            for arg in args:
                arg_type = resolve_data_type(arg["type"])
                param = ParameterImpl(
                    arg["name"],
                    arg_type,
                    prog,
                )

                params.append(param)

        if symbol := symbols.get(name):
            func = func_man.getFunction(symbol.getID())

            return_param = None
            return_type = resolve_data_type(method["rtype"])
            if return_type is not None:
                return_param = ReturnParameterImpl(return_type, prog)

            func.updateFunction(
                THISCALL,
                return_param,
                params,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                False,
                SourceType.USER_DEFINED,
            )

        else:
            tqdm.write(f"- Skipping unknown symbol {name}")

    end(True)


def main(headers_path: Path, pack: bool):
    if headers_path.is_dir():
        iterator = tqdm(list(headers_path.iterdir()), unit="header", leave=False, desc="Processing headers")
    else:
        iterator = [headers_path]

    for header_f in iterator:
        with header_f.open("r") as f:
            header = f.read()

        tqdm.write(header_f.name)

        match = re.search(INTERFACE_REGEX, header)

        if match:
            class_name = match["name"]
            fields: str = match["data"].strip()

            if "struct " in fields:
                tqdm.write("- Detected inline struct definition. Skipping...")
                continue

            fields: list = [field.strip().removesuffix(";") for field in fields.splitlines()][::-1]

            start()
            category = dt_man.createCategory(CategoryPath(f"/{header_f.name}"))
            end(True)

            struct = category.getDataType(class_name)

            if struct is None:
                tqdm.write(f"- Creating struct {class_name}")
                struct = StructureDataType(class_name, 0)

            if pack:
                struct.setToDefaultPacking()

            load_struct_fields(struct, category, fields)

        else:
            tqdm.write(f"- Interface {header_f.stem} not found in header file. Fields won't be loaded")

        matches = re.finditer(METHOD_REGEX, header)

        update_method(header_f.stem, list(matches))


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
        description="Load Objective-C header data into Ghidra (Legacy RegEx Edition)",
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

    args = parser.parse_args()

    prog = getCurrentProgram()
    sym_table = prog.getSymbolTable()
    dt_man = prog.getDataTypeManager()
    func_man = prog.getFunctionManager()
    func_tag_man = func_man.getFunctionTagManager()

    main(**args.__dict__)
