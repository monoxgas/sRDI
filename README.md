# sRDI
Shellcode implementation of Reflective DLL Injection. Supports 

sRDI allows for the conversion of DLL files to position independent shellcode. This is accomplished via two components:
- C project which compiles a PE loader implementation (RDI) to shellcode
- Conversion code which attaches the DLL, RDI, and user data together with a bootstrap

This project is comprised of the following elements:
- **ShellcodeRDI:** Compiles shellcode for the DLL loader
- **NativeLoader:** Converts DLL to shellcode if neccesarry, then injects into memory
- **DotNetLoader:** C# implementation of NativeLoader
- **Python\ConvertToShellcode.py:** Convert DLL to shellcode in place
- **PowerShell\ConvertTo-Shellcode.ps1:** Convert DLL to shellcode in place
- **TestDLL:** Example DLL that includes two exported functions for call on Load and after

## Use Cases / Examples
Before use, I recommend you become familiar with [Reflective DLL Injection](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html) and it's purpose. 

### Convert DLL to shellcode using python
```python
from ShellcodeRDI import *

dll = open("TestDLL_x86.dll", 'rb').read()
shellcode = ConvertToShellcode(dll)
```

### Load DLL into memory using C# loader
```
DotNetLoader.exe TestDLL_x64.dll
```

### Convert DLL with python script and load with Native EXE
```
python ConvertToShellcode.py TestDLL_x64.dll
NativeLoader.exe TestDLL_x64.bin
```

### Convert DLL with powershell and load with Invoke-Shellcode
```powershell
Import-Module .\Invoke-Shellcode.ps1
Import-Module .\ConvertTo-Shellcode.ps1
Invoke-Shellcode -Shellcode (ConvertTo-Shellcode -File TestDLL_x64.dll)
```

## Building
This project is built using Visual Studio 2015 (v140) and Windows SDK 8.1. The python script is written using Python 3.

The Python and Powershell scripts are located at:
- Python\ConvertToShellcode.py
- PowerShell\ConvertTo-Shellcode.ps1

After building the project, the other binaries will be located at:
- bin\NativeLoader.exe
- bin\DotNetLoader.exe
- bin\TestDLL_<arch>.dll
- bin\ShellcodeRDI_<arch>.bin

## Credits
The basis of this project is derived from ["Improved Reflective DLL Injection" from Dan Staples](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html) which itself is derived from the original project by [Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection). 

The project framework for compiling C code as shellcode is taken from [Mathew Graeber's reasearch "PIC_BindShell"](http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html)

The [PEFile project](https://github.com/erocarrera/pefile) is used in the python script for parsing.
