Param (
    [Parameter(Position = 0, Mandatory = $True)]
    [String]
    $InputExe,

    [Parameter(Position = 1, Mandatory = $True)]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $InputMapFile,

    [Parameter(Position = 2, Mandatory = $True)]
    [String]
    $OutputFile
)

# PowerShell v2
if(!$PSScriptRoot){ 
	$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent 
}

. "$PSScriptRoot\Get-PEHeader.ps1"

$PE = Get-PEHeader $InputExe -GetSectionData
$TextSection = $PE.SectionHeaders | Where-Object { $_.Name -eq '.text' }

$MapContents = Get-Content $InputMapFile

$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\.text.+CODE' })[0]

$ShellcodeLength = [Int] "0x$(( $TextSectionInfo -split ' ' | Where-Object { $_ } )[1].TrimEnd('H'))" - 1

Write-Host "Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))"

[IO.File]::WriteAllBytes($OutputFile, $TextSection.RawData[0..$ShellcodeLength])
