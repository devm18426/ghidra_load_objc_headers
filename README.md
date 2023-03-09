# ghidra_load_objc_headers
Rough script to load Objective-C header data into Ghidra.

The Objective-C headers are "parsed" using RegEx and relevant data is inserted into the Ghidra database.

Currently supports the following data:
* Identified interfaces are defined as structs, with their fields set accordingly (names and types)
* Instance method parameters (names and types) are set as well. `__thiscall` convention will be set.

When unknown types are encountered for the first time they are inserted into the Ghidra DB as an empty struct.

When pointers to unknown types are encountered they are inserted as `void *` with comments documenting their original type.

When [Blocks](https://www.cocoawithlove.com/2009/10/how-blocks-are-implemented-and.html) are encountered they are inserted with type `Block_literal *`, where `Block_literal` is an empty struct.

The parsed data is inserted over a bridge implemented with [`ghidra-bridge`](https://github.com/justfoxing/ghidra_bridge) so it may be run in any Python 3 interpreter, however requires the Python 2 server be running within Ghidra.

## Usage

* `pip install -r requirements.txt` or `pipenv install -r requirements.txt`
* Headers may be generated using [`classdump-dyld`](https://github.com/limneos/classdump-dyld), for example:
  
  ```
  classdump-dyld -b -h -o output_directory binary_name
  ```
  
```
   ________    _     __                     
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

usage: ghidra_load_objc_headers.py [-h] [--disable-packing] headers_path

Load Objective-C header data into Ghidra

positional arguments:
  headers               Path to header files (globs supported)

options:
  -h, --help            show this help message and exit
  --disable-packing     Disable struct packing (Default: Enabled)
  -v, --verbose         Set logging verbosity (Default: Least verbosity)
  --no-prog             Disable progress bars (Default: Enabled)
  --skip-vars           Enable skipping of instance variable parsing (Default: Disabled)
  --skip-methods        Enable skipping of class method parsing (Default: Disabled)
  -c BASE_CATEGORY, --base-category BASE_CATEGORY
                        Base category path for all loaded types (Default: objc_loader)
  ```
  
## Known Issues
* Complex field types (e.g. in-place struct definitions) are not handled.
* Self-dependencies are not resolved. Run twice on the same folder for best results.
* Protocol definitions in data type literals are ignored (e.g. `NSObject<NSCoding, UITableViewDelegate>` will resolve simply to `NSObject`).
* Properties are ignored.