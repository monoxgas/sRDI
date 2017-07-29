from ShellcodeRDI import *

if len(sys.argv) != 2:
    print('Usage: RDIShellcodePyConverter.py [DLL File]')
    sys.exit()

print('Creating Shellcode: {}'.format(sys.argv[1].replace('.dll', '.bin')))
dll = open(sys.argv[1], 'rb').read()

if len(dll) > 0: convertedDLL = ConvertToShellcode(dll, HashFunctionName("SayHello"))

with open(sys.argv[1].replace('.dll', '.bin'), 'wb') as f:
    f.write(convertedDLL)