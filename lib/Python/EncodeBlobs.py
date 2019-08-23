import argparse
import os
import sys

StartMarker = 'MARKER:S'
EndMarker  = 'MARKER:E'

NativeTemplate = """
    LPSTR rdiShellcode32 = "{}";
    LPSTR rdiShellcode64 = "{}";
    DWORD rdiShellcode32Length = {}, rdiShellcode64Length = {};
    """

DotNetTemplate = """
            var rdiShellcode32 = new byte[] {{ {} }};
            var rdiShellcode64 = new byte[] {{ {} }};
            """

PythonTemplate = """
    rdiShellcode32 = b'{}'
    rdiShellcode64 = b'{}'
    """

def main():
    parser = argparse.ArgumentParser(description='sRDI Blob Encoder', conflict_handler='resolve')
    parser.add_argument('solution_dir', help='Solution Directory')
    arguments = parser.parse_args()

    binFile32 = os.path.join(arguments.solution_dir, 'bin', 'ShellcodeRDI_x86.bin')
    binFile64 = os.path.join(arguments.solution_dir, 'bin', 'ShellcodeRDI_x64.bin')

    native_file = os.path.join(arguments.solution_dir, 'Native/Loader.cpp')
    dotnet_file = os.path.join(arguments.solution_dir, 'DotNet/Program.cs')
    python_file = os.path.join(arguments.solution_dir, 'Python/ShellcodeRDI.py')
    posh_file = os.path.join(arguments.solution_dir, 'PowerShell/ConvertTo-Shellcode.ps1')

    if not os.path.isfile(binFile32) or not os.path.isfile(binFile64):
        print("[!] ShellcodeRDI_x86.bin and ShellcodeRDI_x64.bin files weren't in the bin directory")
        return

    binData32 = open(binFile32, 'rb').read()
    binData64 = open(binFile64, 'rb').read()

    # Patch the native loader

    native_insert = NativeTemplate.format(
        ''.join('\\x{:02X}'.format(b) for b in binData32),
        ''.join('\\x{:02X}'.format(b) for b in binData64),
        len(binData32), len(binData64)
    )

    code = open(native_file, 'r').read()
    start = code.find(StartMarker) + len(StartMarker)
    end = code.find(EndMarker) - 2 # for the //
    code = code[:start] + native_insert + code[end:] 
    open(native_file, 'w').write(code)

    print('[+] Updated {}'.format(native_file))


    # Patch the DotNet loader

    dotnet_insert = DotNetTemplate.format(
        ','.join('0x{:02X}'.format(b) for b in binData32),
        ','.join('0x{:02X}'.format(b) for b in binData64)
    )

    code = open(dotnet_file, 'r').read()
    start = code.find(StartMarker) + len(StartMarker)
    end = code.find(EndMarker) - 2 # for the //
    code = code[:start] + dotnet_insert + code[end:] 
    open(dotnet_file, 'w').write(code)

    print('[+] Updated {}'.format(dotnet_file))


    # Patch the Python loader

    python_insert = PythonTemplate.format(
        ''.join('\\x{:02X}'.format(b) for b in binData32),
        ''.join('\\x{:02X}'.format(b) for b in binData64)
    )

    code = open(python_file, 'r').read()
    start = code.find(StartMarker) + len(StartMarker)
    end = code.find(EndMarker) - 1 # for the #
    code = code[:start] + python_insert + code[end:] 
    open(python_file, 'w').write(code)

    print('[+] Updated {}'.format(python_file))


    # Patch the PowerShell loader

    posh_insert = DotNetTemplate.format(
        ','.join('0x{:02X}'.format(b) for b in binData32),
        ','.join('0x{:02X}'.format(b) for b in binData64)
    )

    code = open(posh_file, 'r').read()
    start = code.find(StartMarker) + len(StartMarker)
    end = code.find(EndMarker) - 2 # for the //
    code = code[:start] + posh_insert + code[end:] 
    open(posh_file, 'w').write(code)

    print('[+] Updated {}'.format(posh_file))


    print("")

if __name__ == '__main__':
    main()
