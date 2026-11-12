using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace UltimateWindows.NativeInterop.Security;

public static class ElevationChecker
{
    public static bool IsRunningAsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}

/// <summary>
/// Проверка криптографической подписи Authenticode (WinVerifyTrust):
/// 1) Встроенная подпись PE-файла (WTD_CHOICE_FILE);
/// 2) Системная каталожная подпись Windows (.cat в CatRoot через CryptCATAdmin*), которой подписаны штатные файлы System32 (dwm.exe, conhost.exe, notepad.exe и др.).
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");
    private static readonly ConcurrentDictionary<string, bool> VerifiedCatalogCache = new(StringComparer.OrdinalIgnoreCase);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

    public static bool IsFileTrustedSigned(string filePath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        var fullPath = Path.GetFullPath(filePath);
        int embeddedStatus = VerifyEmbeddedSignatureStatus(fullPath);
        if (embeddedStatus == 0)
        {
            return true;
        }

        // Если встроенной подписи в PE нет (TRUST_E_NOSIGNATURE), проверяем системный каталог подписей Windows CatRoot
        if (embeddedStatus == TRUST_E_NOSIGNATURE)
        {
            return IsCatalogSigned(fullPath);
        }

        return false;
    }

    private static int VerifyEmbeddedSignatureStatus(string fullPath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(fullPath),
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = fileInfoPtr,
            dwStateAction = WTD_STATEACTION_VERIFY,
            hWVTStateData = IntPtr.Zero
        };

        try
        {
            var actionGuid = WinTrustActionGenericVerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
        }
        finally
        {
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            var closeGuid = WinTrustActionGenericVerifyV2;
            _ = WinVerifyTrust(IntPtr.Zero, ref closeGuid, ref trustData);

            if (fileInfo.pcwszFilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
            }

            Marshal.FreeCoTaskMem(fileInfoPtr);
        }
    }

    private static bool IsCatalogSigned(string fullPath)
    {
        var subsystem = DriverActionVerify;
        if (!CryptCATAdminAcquireContext2(out var hCatAdmin, ref subsystem, null, IntPtr.Zero, 0) &&
            !CryptCATAdminAcquireContext(out hCatAdmin, ref subsystem, 0))
        {
            return false;
        }

        try
        {
            using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint hashLen = 64;
            byte[] hash = new byte[hashLen];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, hash, 0))
            {
                if (hashLen is > 64 and <= 512)
                {
                    hash = new byte[hashLen];
                    if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, hash, 0))
                    {
                        return false;
                    }
                }
                else
                {
                    hashLen = 64;
                    if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref hashLen, hash, 0))
                    {
                        return false;
                    }
                }
            }

            IntPtr prevCat = IntPtr.Zero;
            while (true)
            {
                var hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, ref prevCat);
                if (hCatInfo == IntPtr.Zero)
                {
                    break;
                }

                prevCat = hCatInfo;
                var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0) &&
                    !string.IsNullOrWhiteSpace(catInfo.wszCatalogFile) &&
                    File.Exists(catInfo.wszCatalogFile))
                {
                    bool catTrusted = VerifiedCatalogCache.GetOrAdd(
                        catInfo.wszCatalogFile,
                        static catPath => VerifyEmbeddedSignatureStatus(catPath) == 0);

                    if (catTrusted)
                    {
                        _ = CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                        return true;
                    }
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            _ = CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [In] ref Guid pgActionID,
        [In, Out] ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext(
        out IntPtr phCatAdmin,
        [In] ref Guid pgSubsystem,
        uint dwFlags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        [In] ref Guid pgSubsystem,
        string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        IntPtr hFile,
        ref uint pcbHash,
        [Out] byte[] pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref uint pcbHash,
        [Out] byte[] pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        [In] byte[] pbHash,
        uint cbHash,
        uint dwFlags,
        ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr hCatAdmin,
        uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
