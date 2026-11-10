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
/// Проверка криптографической подписи Authenticode (WinVerifyTrust) для всех скачиваемых пакетов VC++, DirectX и драйверов.
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    public static bool IsFileTrustedSigned(string filePath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(Path.GetFullPath(filePath)),
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
            var status = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
            return status == 0;
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

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [In] ref Guid pgActionID,
        [In, Out] ref WINTRUST_DATA pWVTData);

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
