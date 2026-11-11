using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using UltimateWindows.Modules.Optimizer.Models;

namespace UltimateWindows.NativeInterop.Optimizer;

/// <summary>
/// Собирает сведения о компьютере, от которых зависит применимость твиков:
/// сборку Windows, тип системного диска (SSD или жёсткий диск), наличие батареи и объём памяти.
/// Права администратора не нужны. Факт, который выяснить не удалось, возвращается как null.
/// </summary>
public static class WindowsSystemFactsProbe
{
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const int StorageDeviceSeekPenaltyProperty = 7;

    private const byte BatteryFlagNoSystemBattery = 128;
    private const byte BatteryFlagUnknown = 255;

    public static SystemFacts Collect()
    {
        if (!OperatingSystem.IsWindows())
        {
            return SystemFacts.Unknown;
        }

        return new SystemFacts(
            WindowsBuildNumber: Environment.OSVersion.Version.Build,
            SystemDriveIsSolidState: TryDetectSolidStateSystemDrive(),
            HasBattery: TryDetectBattery(),
            TotalMemoryBytes: TryGetTotalMemoryBytes());
    }

    /// <summary>
    /// Спрашивает у системного тома, есть ли у накопителя задержка на перемещение головок.
    /// Её нет у SSD и NVMe и она есть у жёстких дисков.
    /// </summary>
    private static bool? TryDetectSolidStateSystemDrive()
    {
        var root = Path.GetPathRoot(Environment.SystemDirectory);
        if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':')
        {
            return null;
        }

        // Нулевой уровень доступа позволяет опрашивать свойства тома без прав администратора
        var volumePath = $@"\\.\{root[0]}:";
        using var handle = CreateFileW(
            volumePath,
            0,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            return null;
        }

        const int querySize = 12;   // STORAGE_PROPERTY_QUERY: PropertyId, QueryType, AdditionalParameters
        const int resultSize = 12;  // DEVICE_SEEK_PENALTY_DESCRIPTOR: Version, Size, IncursSeekPenalty

        var queryBuffer = Marshal.AllocHGlobal(querySize);
        var resultBuffer = Marshal.AllocHGlobal(resultSize);
        try
        {
            Marshal.WriteInt32(queryBuffer, 0, StorageDeviceSeekPenaltyProperty);
            Marshal.WriteInt32(queryBuffer, 4, 0);
            Marshal.WriteInt32(queryBuffer, 8, 0);

            Marshal.WriteInt32(resultBuffer, 0, 0);
            Marshal.WriteInt32(resultBuffer, 4, 0);
            Marshal.WriteInt32(resultBuffer, 8, 0);

            var succeeded = DeviceIoControl(
                handle,
                IoctlStorageQueryProperty,
                queryBuffer,
                querySize,
                resultBuffer,
                resultSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!succeeded || bytesReturned < 9)
            {
                // Так отвечают, например, некоторые RAID-контроллеры: тип диска остаётся неизвестным
                return null;
            }

            var incursSeekPenalty = Marshal.ReadByte(resultBuffer, 8) != 0;
            return !incursSeekPenalty;
        }
        finally
        {
            Marshal.FreeHGlobal(queryBuffer);
            Marshal.FreeHGlobal(resultBuffer);
        }
    }

    private static bool? TryDetectBattery()
    {
        if (!GetSystemPowerStatus(out var status))
        {
            return null;
        }

        return status.BatteryFlag switch
        {
            BatteryFlagUnknown => null,
            BatteryFlagNoSystemBattery => false,
            _ => true
        };
    }

    private static long? TryGetTotalMemoryBytes()
    {
        var total = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        return total > 0 ? total : null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }
}
