function Get-FunctionHash
{
<#
.SYNOPSIS

    Outputs a module and function hash that can be passed to the
    GetProcAddressWithHash function.

    PowerSploit Function: Get-FunctionHash
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    Get-FunctionHash calculates a hash that can be passed to
    GetProcAddressWithHash - a C function that is used to resolve Win32
    library functions. Passing a hash to a function address resolver
    prevents plaintext strings from being sent in the clear in shellcode.

    A python implementation of this algorithm is present in Meatsploit
    will perform hash collision detection.

.PARAMETER Module

    Specifies the module to be hashed. Be sure to include the file extension.
    The module name will be normalized to upper case.

.PARAMETER Function

    Specifies the function to be hashed. The function name is case-sensitive.

.PARAMETER RorValue

    Specifies the value by which the hashing algorithm rotates right. The
    range of possibles values is 1-31.

.EXAMPLE

    Get-FunctionHash kernel32.dll LoadLibraryA

.OUTPUTS

    System.String

    Outputs a hexadecimal representation of the function hash.

.LINK

    http://www.exploit-monday.com/
    https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/hash.py
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Function,

        [Parameter(Position = 2)]
        [ValidateRange(1, 31)]
        [String]
        $RorValue = 13
    )

    $MethodInfo = New-Object Reflection.Emit.DynamicMethod('Ror', [UInt32], @([UInt32], [UInt32]))
    $ILGen = $MethodInfo.GetILGenerator(8)

    # C# equivalent of: return x >> n | x << 32 - n;
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_1)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_S, 31)
    $ILGen.Emit([Reflection.Emit.OpCodes]::And)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Shr_Un)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_S, 32)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_1)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Sub)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_S, 31)
    $ILGen.Emit([Reflection.Emit.OpCodes]::And)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Shl)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Or)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ret)

    $Delegate = [Func``3[UInt32, UInt32, UInt32]]

    $Ror = $MethodInfo.CreateDelegate($Delegate)

    $MethodInfo = New-Object Reflection.Emit.DynamicMethod('Add', [UInt32], @([UInt32], [UInt32]))
    $ILGen = $MethodInfo.GetILGenerator(2)

    # C# equivalent of: return x + y;
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_1)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Add)
    $ILGen.Emit([Reflection.Emit.OpCodes]::Ret)

    $Add = $MethodInfo.CreateDelegate($Delegate)

    $UnicodeEncoder = [Text.Encoding]::Unicode

    $Module = $Module.ToUpper()
    [Byte[]] $ModuleBytes = $UnicodeEncoder.GetBytes($Module) + [Byte[]] @(0, 0)
    $ModuleHash = [UInt32] 0

    # Iterate over each byte of the unicode module string including nulls
    for ($i = 0; $i -lt $ModuleBytes.Length; $i++)
    {
        $ModuleHash = $Ror.Invoke($ModuleHash, 13)
        $ModuleHash = $Add.Invoke($ModuleHash, $ModuleBytes[$i])
    }

    $AsciiEncoder = [Text.Encoding]::ASCII
    [Byte[]] $FunctionBytes = $AsciiEncoder.GetBytes($Function) + @([Byte] 0)
    $FunctionHash = [UInt32] 0

    # Iterate over each byte of the function string including the null terminator
    for ($i = 0; $i -lt $FunctionBytes.Length; $i++)
    {
        $FunctionHash = $Ror.Invoke($FunctionHash, $RorValue)
        $FunctionHash = $Add.Invoke($FunctionHash, $FunctionBytes[$i])
    }

    # Add the function hash to the module hash
    $FinalHash = $Add.Invoke($ModuleHash, $FunctionHash)

    # Write out the hexadecimal representation of the hash
    Write-Output "0x$($FinalHash.ToString('X8'))"
}