import argparse
from ShellcodeRDI import *

__version__ = '1.1'

def main():
    parser = argparse.ArgumentParser(description='RDI Shellcode Converter', conflict_handler='resolve')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
    parser.add_argument('input_dll', help='DLL to convert to shellcode')
    parser.add_argument('-f', '--function-name', dest='function_name', default='SayHello', help='The function to call after DllMain')
    parser.add_argument('-c', '--clear-header', dest='clear_header', action="store_true", help='Clear the PE header on load')
    arguments = parser.parse_args()

    input_dll = arguments.input_dll
    output_bin = input_dll.replace('.dll', '.bin')

    print('Creating Shellcode: {}'.format(output_bin))
    dll = open(arguments.input_dll, 'rb').read()

    flags = 0

    if arguments.clear_header:
        flags |= 0x1

    converted_dll = ConvertToShellcode(dll, HashFunctionName(arguments.function_name), b'dave', flags)

    with open(output_bin, 'wb') as f:
        f.write(converted_dll)

if __name__ == '__main__':
    main()
