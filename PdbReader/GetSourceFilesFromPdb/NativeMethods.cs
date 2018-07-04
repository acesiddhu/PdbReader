using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.TeamFoundation.Build.Workflow
{
    internal class DbgHelpWrapper : IDisposable
    {
        public DbgHelpWrapper()
        {
            m_processHandle = Process.GetCurrentProcess().Handle;

            if (m_processHandle == IntPtr.Zero)
            {
                //throw new Win32ErrorWrapperException("Process.Handle");
            }

            if (!NativeMethods.SymInitialize(m_processHandle,
                                             null,
                                             false))
            {
                m_processHandle = IntPtr.Zero;
                //throw new Win32ErrorWrapperException("SymInitialize");
            }

            NativeMethods.SymSetOptions(NativeMethods.SymOptions.SYMOPT_NO_IMAGE_SEARCH);
        }

        public void Dispose()
        {
            if (m_processHandle != IntPtr.Zero)
            {
                Boolean cleanup = NativeMethods.SymCleanup(m_processHandle);
                m_processHandle = IntPtr.Zero;

                if (!cleanup)
                {
                    //throw new Win32ErrorWrapperException("SymCleanup");
                }
            }
        }

        public List<String> GetIndexedSources(String symbolsFile)
        {
            List<String> referencedSourceFiles = new List<String>();
            UInt64 moduleBase = 0;

            // Opens the symbols file
            using (FileStream fs = new FileStream(symbolsFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.None))
            {
                SafeFileHandle fileHandle = fs.SafeFileHandle;

                if (fileHandle.IsInvalid)
                {
                    //throw new Win32ErrorWrapperException("SafeFileHandle.IsInvalid");
                }

                // SymSrvGetFileIndexesW extracts symbol server index information from executable 
                // images and pdb. It will return false if the file is not one of them.
                Guid guid = Guid.Empty;
                UInt32 val1 = 0;
                UInt32 val2 = 0;
                if (!NativeMethods.SymSrvGetFileIndexes(symbolsFile,
                                                        ref guid,
                                                        ref val1,
                                                        ref val2,
                                                        0))
                {
                    //throw new GetIndexedSourcesException(symbolsFile, ActivitiesResources.Get(ActivitiesResources.GetIndexedSourcesError_NoSymbolIndexes));
                }

                // Loads the symbols file in DbgHelp
                String moduleName = Path.GetFileNameWithoutExtension(symbolsFile);
                moduleBase = NativeMethods.SymLoadModuleEx(m_processHandle,
                                                           fileHandle,
                                                           symbolsFile,
                                                           moduleName,
                                                           1000000,
                                                           1,
                                                           IntPtr.Zero,
                                                           0);
            }

            try
            {
                // Reads the module info. If the pdb file does not have symbol information or is not pdb type, stops the process
                NativeMethods.IMAGEHLP_MODULE64 moduleInfo = new NativeMethods.IMAGEHLP_MODULE64();
                moduleInfo.SizeOfStruct = (UInt32)Marshal.SizeOf(moduleInfo);
                if (!NativeMethods.SymGetModuleInfo64(m_processHandle,
                                                      moduleBase,
                                                      ref moduleInfo))
                {
                    //throw new GetIndexedSourcesException(symbolsFile, ActivitiesResources.Get(ActivitiesResources.GetIndexedSourcesError_NoSymbolInformation));
                }

                if (moduleInfo.SymType != NativeMethods.SymType.SymPdb)
                {
                    //throw new GetIndexedSourcesException(symbolsFile, ActivitiesResources.Get(ActivitiesResources.GetIndexedSourcesError_NoSymbolPdb));
                }

                // Enumerates the indexed source files if the pdb file has source information
                if (moduleInfo.LineNumbers)
                {
                    // Callback that processes the found source file from the pdb
                    NativeMethods.SymEnumSourceFilesProc enumSourceFilesCallBack = delegate (ref NativeMethods.SOURCEFILE pSourceFile, IntPtr UserContext)
                    {
                        if (pSourceFile.FileName != IntPtr.Zero)
                        {
                            referencedSourceFiles.Add(Marshal.PtrToStringUni(pSourceFile.FileName));
                        }

                        return true;
                    };

                    // Enumerates the indexed source files
                    if (!NativeMethods.SymEnumSourceFiles(m_processHandle,
                                                          moduleBase,
                                                          null,
                                                          enumSourceFilesCallBack,
                                                          IntPtr.Zero))
                    {
                        //throw new Win32ErrorWrapperException("SymEnumSourceFiles");
                    }
                }
            }
            finally
            {
                // Unloads the module
                if (moduleBase > 0)
                {
                    if (!NativeMethods.SymUnloadModule64(m_processHandle,
                                                         moduleBase))
                    {
                        //throw new Win32ErrorWrapperException("SymUnloadModule64");
                    }
                }
            }

            return referencedSourceFiles;
        }

        private IntPtr m_processHandle;
    }

    internal static class NativeMethods
    {
        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymInitializeW")]
        internal static extern bool SymInitialize(
            IntPtr hProcess,
            string UserSearchPath,
            bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool SymCleanup(
            IntPtr hProcess);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SymOptions SymSetOptions(
            SymOptions SymOptions);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymLoadModuleExW")]
        internal static extern ulong SymLoadModuleEx(
            IntPtr hProcess,
            SafeFileHandle hFile,
            string ImageName,
            string ModuleName,
            ulong BaseOfDll,
            uint DllSize,
            IntPtr Data,
            uint Flags);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymGetModuleInfoW64")]
        internal static extern bool SymGetModuleInfo64(
            IntPtr hProcess,
            ulong dwAddr,
            ref IMAGEHLP_MODULE64 ModuleInfo);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymEnumSourceFilesW")]
        internal static extern bool SymEnumSourceFiles(
            IntPtr hProcess,
            ulong ModeBase,
            string Mask,
            SymEnumSourceFilesProc EnumSymbolsCallback,
            IntPtr UserContext);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SymSrvGetFileIndexesW")]
        internal static extern bool SymSrvGetFileIndexes(
            string file,
            ref Guid Id,
            ref uint Val1,
            ref uint Val2,
            uint Flags);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool SymUnloadModule64(
            IntPtr hProcess,
            ulong BaseOfDll);

        internal delegate bool SymEnumSourceFilesProc(
            ref SOURCEFILE pSourceFile,
            IntPtr UserContext);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct IMAGEHLP_MODULE64
        {
            public uint SizeOfStruct;
            public ulong BaseOfImage;
            public uint ImageSize;
            public uint TimeDateStamp;
            public uint CheckSum;
            public uint NumSyms;
            public SymType SymType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string ModuleName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ImageName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string LoadedImageName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string LoadedPdbName;
            public uint CVSig;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 780)]
            public string CVData;
            public uint PdbSig;
            public Guid PdbSig70;
            public uint PdbAge;
            public bool PdbUnmatched;
            public bool DbgUnmatched;
            public bool LineNumbers;
            public bool GlobalSymbols;
            public bool TypeInfo;
            public bool SourceIndexed;
            public bool Publics;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SOURCEFILE
        {
            public ulong ModeBase;
            public IntPtr FileName;
        }

        [Flags]
        public enum SymType : uint
        {
            SymNone,
            SymCoff,
            SymCv,
            SymPdb,
            SymExport,
            SymDeferred,
            SymSym,
            SymDia,
            SymVirtual,
        }

        [Flags]
        public enum SymOptions : uint
        {
            SYMOPT_ALLOW_ABSOLUTE_SYMBOLS = 0x00000800,
            SYMOPT_ALLOW_ZERO_ADDRESS = 0x01000000,
            SYMOPT_AUTO_PUBLICS = 0x00010000,
            SYMOPT_CASE_INSENSITIVE = 0x00000001,
            SYMOPT_DEBUG = 0x80000000,
            SYMOPT_DEFERRED_LOADS = 0x00000004,
            SYMOPT_DISABLE_SYMSRV_AUTODETECT = 0x02000000,
            SYMOPT_EXACT_SYMBOLS = 0x00000400,
            SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200,
            SYMOPT_FAVOR_COMPRESSED = 0x00800000,
            SYMOPT_FLAT_DIRECTORY = 0x00400000,
            SYMOPT_IGNORE_CVREC = 0x00000080,
            SYMOPT_IGNORE_IMAGEDIR = 0x00200000,
            SYMOPT_IGNORE_NT_SYMPATH = 0x00001000,
            SYMOPT_INCLUDE_32BIT_MODULES = 0x00002000,
            SYMOPT_LOAD_ANYTHING = 0x00000040,
            SYMOPT_LOAD_LINES = 0x00000010,
            SYMOPT_NO_CPP = 0x00000008,
            SYMOPT_NO_IMAGE_SEARCH = 0x00020000,
            SYMOPT_NO_PROMPTS = 0x00080000,
            SYMOPT_NO_PUBLICS = 0x00008000,
            SYMOPT_NO_UNQUALIFIED_LOADS = 0x00000100,
            SYMOPT_OVERWRITE = 0x00100000,
            SYMOPT_PUBLICS_ONLY = 0x00004000,
            SYMOPT_SECURE = 0x00040000,
            SYMOPT_UNDNAME = 0x00000002,
        };
    }
}
