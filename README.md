# ghidra_load_objc_headers
Rough script to load Objective-C header data into Ghidra.

The Objective-C headers are "parsed" using RegEx and relevant data is inserted into the Ghidra database.

Currently supports the following data:
* Identified interfaces are defined as structs, with their fields set accordingly (names and types)
* Instance method parameters (names and types) are set as well. Sets `__thiscall` convention.

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

usage: ghidra_load_objc_headers.py [-h] headers_path

Load Objective-C header data into Ghidra

positional arguments:
  headers_path  Path to single header file or directory containing headers

options:
  -h, --help    show this help message and exit
  ```
  
## Known Issues
* ObjC Blocks are not handled at all.
* Complex field types (e.g. in-place struct definitions) are not handled.