import argparse
import os
import sys

def main():
    parser = argparse.ArgumentParser(description='sRDI Blob Encoder', conflict_handler='resolve')
    parser.add_argument('bin_directory', help='Bin directory containing ShellcodeRDI_xXX.bin files')
    arguments = parser.parse_args()

    binFile32 = os.path.join(arguments.bin_directory, 'ShellcodeRDI_x86.bin')
    binFile64 = os.path.join(arguments.bin_directory, 'ShellcodeRDI_x64.bin')

    if not os.path.isfile(binFile32) or not os.path.isfile(binFile64):
        print("[!] ShellcodeRDI_x86.bin and ShellcodeRDI_x64.bin files weren't in the bin directory")
        return

    binData32 = open(binFile32, 'rb').read()
    binData64 = open(binFile64, 'rb').read()

    print('[+] \\x escaped strings:\n')
    print('rdiShellcode32 = "{}"\n'.format(
        ''.join('\\x{:02X}'.format(b) for b in binData32)
        ))
    print('rdiShellcode64 = "{}"\n'.format(
        ''.join('\\x{:02X}'.format(b) for b in binData64)
        ))

    print('\n\n[+] 0x escaped strings:\n')
    print('var rdiShellcode32 = new byte[] {{ {} }};\n'.format(
        ','.join('0x{:02X}'.format(b) for b in binData32)
        ))
    print('var rdiShellcode64 = new byte[] {{ {} }};\n'.format(
        ','.join('0x{:02X}'.format(b) for b in binData64)
        ))

    print('\n[+] Final Lengths:\n')
    print("rdiShellcode32 Length: {}".format(len(binData32)))
    print("rdiShellcode64 Lenght: {}".format(len(binData64)))

    print("")

if __name__ == '__main__':
    main()
