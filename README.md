# idatocpp

A tool that allows you to generate function wrappers for classes from your IDB file.

## Installation

Copy all dlls from "IDA 7.2 plugins" folder to your IDA 7.2 plugins folder.

## Usage

1) Start IDA, Edit > Plugins > Export to Plugin-SDK. Select a folder of your choice and extract.

2) Run the program like this: `idatocpp.py -db "<PathToPluginSDKOutput>\database" -iclass ClassNameHere --rcalls`

3) An output folder will be created along with the header and source file for the class. That's all.

### idatocpp.py options 

```
header_cpp_gen.py [-h] -db path -iclass name [--rcalls] [--pdtypes]

help:
-h, --help    show this help message and exit

required arguments:
  -db path      The path to IDA generated database using plugin-sdk tool.
  -iclass name  The class name in the IDB.
  
optional arguments:
  --rcalls      Adds <className>_Reversed wrappers for virtual functions.
  --pdtypes     Function parameter types will be extracted from the demangled name 
                rather than the function prototype.
```

## Supported calling conventions

- cdecl, thiscall, stdcall, and fastcall

## Credits 

I used the [plugin-sdk export tool](https://github.com/DK22Pac/plugin-sdk-tools) for this project. I modified it to make it easier to work with.