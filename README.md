# ghidra_load_objc_headers
Rough script to load Objective-C header data into Ghidra.

The Objective-C headers are "parsed" using RegEx and relevant data is inserted into the Ghidra database.

Currently supports the following data:
* Identified interfaces are defined as structs, with their fields set accordingly (names and types)
* Method parameters (names and types) are set as well. Assumes and sets `__thiscall` convention.

The parsed data is inserted over a bridge implemented with [`ghidra-bridge`](https://github.com/justfoxing/ghidra_bridge) so it may be run in any Python 3 interpreter, however requires the Python 2 server be running within Ghidra.

## Usage

* `pip install -r requirements.txt` or `pipenv install -r requirements.txt`
* Headers may be generated using `classdump-dyld`, for example:
  
  ```
  classdump-dyld -b -h -o output_directory binary_name
  ```
  
## Known Issues
* ObjC Blocks are not handled at all.