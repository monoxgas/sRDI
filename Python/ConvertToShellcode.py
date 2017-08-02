import argparse
from ShellcodeRDI import *

__version__ = '1.0'

def main():
    parser = argparse.ArgumentParser(description='RDI Shellcode Converter', conflict_handler='resolve')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
    parser.add_argument('input_rdll', help='RDLL to convert to shellcode')
    parser.add_argument('-f', '--function-name', dest='function_name', default='SayHello', help='The function to call after DllMain')
    arguments = parser.parse_args()

    input_rdll = arguments.input_rdll
    output_bin = input_rdll.replace('.dll', '.bin')

    print('Creating Shellcode: {}'.format(output_bin))
    dll = open(arguments.input_rdll, 'rb').read()

    converted_dll = ConvertToShellcode(dll, HashFunctionName(arguments.function_name))
    with open(output_bin, 'wb') as f:
        f.write(converted_dll)

if __name__ == '__main__':
    main()
