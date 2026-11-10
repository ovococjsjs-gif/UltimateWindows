using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Safety.Storage;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Restore;

/// <summary>
/// Умный координатор системных точек восстановления Windows (VSS) с защитой от спама теневых копий.
/// Создает точку только при крупных операциях и не чаще чем раз в RestorePointCooldownHours (по умолчанию 24 ч).
/// </summary>
public sealed class WindowsSystemRestoreBridge : IRestorePointProvider
{
    private const int BEGIN_SYSTEM_CHANGE = 100;
    private const int END_SYSTEM_CHANGE = 101;
    private const int MODIFY_SETTINGS = 12;
    private const string LastRestorePointSettingKey = "last_vss_restore_point_utc";

    private readonly SqliteVaultRepository _repository;
    private readonly Func<VaultQuotaPolicy> _policyAccessor;

    public WindowsSystemRestoreBridge(SqliteVaultRepository repository, Func<VaultQuotaPolicy> policyAccessor)
    {
        _repository = repository;
        _policyAccessor = policyAccessor;
    }

    public async Task<bool> TryCreateRestorePointIfNeededAsync(
        string description,
        bool forceMajorOperation = false,
        CancellationToken ct = default)
    {
        if (!forceMajorOperation)
        {
            // Для легких повседневных твиков не засоряем System Volume Information —
            // работает наш компактный КБ-журнал отката в SQLite.
            return false;
        }

        if (!OperatingSystem.IsWindows() || !ElevationChecker.IsRunningAsAdministrator())
        {
            return false;
        }

        var policy = _policyAccessor();
        var lastRaw = await _repository.GetSettingAsync(LastRestorePointSettingKey, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(lastRaw) &&
            DateTimeOffset.TryParse(lastRaw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var lastCreated))
        {
            var elapsed = DateTimeOffset.UtcNow - lastCreated;
            if (elapsed.TotalHours < policy.RestorePointCooldownHours)
            {
                return false;
            }
        }

        var safeTitle = string.IsNullOrWhiteSpace(description)
            ? "UltimateWindows Safe Checkpoint"
            : description.Length > 200 ? description[..200] : description;

        var beginInfo = new RESTOREPOINTINFOW
        {
            dwEventType = BEGIN_SYSTEM_CHANGE,
            dwRestorePtType = MODIFY_SETTINGS,
            llSequenceNumber = 0,
            szDescription = safeTitle
        };

        if (!SRSetRestorePointW(ref beginInfo, out var status) || status.nStatus != 0)
        {
            return false;
        }

        var endInfo = new RESTOREPOINTINFOW
        {
            dwEventType = END_SYSTEM_CHANGE,
            dwRestorePtType = MODIFY_SETTINGS,
            llSequenceNumber = status.llSequenceNumber,
            szDescription = safeTitle
        };

        _ = SRSetRestorePointW(ref endInfo, out _);

        await _repository.SaveSettingAsync(
            LastRestorePointSettingKey,
            DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            ct).ConfigureAwait(false);

        return true;
    }

    [DllImport("srclient.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SRSetRestorePointW(
        [In] ref RESTOREPOINTINFOW pRestorePtSpec,
        out STATEMGRSTATUS pSMgrStatus);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RESTOREPOINTINFOW
    {
        public int dwEventType;
        public int dwRestorePtType;
        public long llSequenceNumber;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szDescription;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STATEMGRSTATUS
    {
        public uint nStatus;
        public long llSequenceNumber;
    }
}

/// <summary>
/// Модель сериализации состояния значения реестра для точного отката.
/// </summary>
public sealed record RegistryValueSnapshot(
    string Hive,
    string SubKey,
    string ValueName,
    bool ExistedBefore,
    RegistryValueKind ValueKind,
    string? SerializedData);

/// <summary>
/// Полноценный исполнитель откатов для Windows: восстанавливает значения реестра, видеорежимы монитора, схемы питания и файлы из карантина.
/// </summary>
public sealed class WindowsSystemStateApplier : DefaultFileStateApplier
{
    private readonly UltimateWindows.NativeInterop.Hardware.WindowsHardwarePlatformProvider _hardwareProvider = new();

    public override async Task ApplyRollbackDeltaAsync(
        StateDeltaRecord delta,
        Func<string, CancellationToken, Task<byte[]>> restoreBlobBytesAsync,
        CancellationToken ct = default)
    {
        if (delta.TargetKind == StateTargetKind.RegistryValue &&
            OperatingSystem.IsWindows() &&
            !string.IsNullOrWhiteSpace(delta.PreviousStateJson))
        {
            var snapshot = JsonSerializer.Deserialize<RegistryValueSnapshot>(delta.PreviousStateJson);
            if (snapshot is not null)
            {
                RestoreRegistrySnapshot(snapshot);
            }

            return;
        }

        if (delta.TargetKind == StateTargetKind.SystemSetting &&
            OperatingSystem.IsWindows() &&
            !string.IsNullOrWhiteSpace(delta.PreviousStateJson))
        {
            if (delta.TargetPath.StartsWith("DisplayRefreshRate:", StringComparison.OrdinalIgnoreCase))
            {
                using var doc = JsonDocument.Parse(delta.PreviousStateJson);
                var dev = doc.RootElement.TryGetProperty("Device", out var dEl) ? dEl.GetString() : null;
                var hz = doc.RootElement.TryGetProperty("RefreshHz", out var hEl) ? hEl.GetInt32() : 0;
                if (!string.IsNullOrWhiteSpace(dev) && hz > 0)
                {
                    _ = await _hardwareProvider.TrySetDisplayRefreshRateAsync(dev, hz, ct).ConfigureAwait(false);
                }

                return;
            }

            if (string.Equals(delta.TargetPath, "PowerActiveScheme", StringComparison.OrdinalIgnoreCase))
            {
                using var doc = JsonDocument.Parse(delta.PreviousStateJson);
                if (doc.RootElement.TryGetProperty("SchemeGuid", out var gEl) &&
                    Guid.TryParse(gEl.GetString(), out var prevScheme))
                {
                    _ = await _hardwareProvider.TrySetActivePowerSchemeAsync(prevScheme, ct).ConfigureAwait(false);
                }

                return;
            }

            if (delta.TargetPath.StartsWith("DnsProfile:", StringComparison.OrdinalIgnoreCase))
            {
                _ = await UltimateWindows.NativeInterop.Optimizer.WindowsOptimizerPlatformBridge
                    .RestoreDnsSnapshotJsonAsync(delta.PreviousStateJson, ct)
                    .ConfigureAwait(false);
                return;
            }
        }

        await base.ApplyRollbackDeltaAsync(delta, restoreBlobBytesAsync, ct).ConfigureAwait(false);
    }

    private static void RestoreRegistrySnapshot(RegistryValueSnapshot snapshot)
    {
        var hive = snapshot.Hive.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKU" or "HKEY_USERS" => RegistryHive.Users,
            _ => RegistryHive.CurrentUser
        };

        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        if (!snapshot.ExistedBefore)
        {
            using var subKey = baseKey.OpenSubKey(snapshot.SubKey, writable: true);
            subKey?.DeleteValue(snapshot.ValueName, throwOnMissingValue: false);
            return;
        }

        using var writableKey = baseKey.CreateSubKey(snapshot.SubKey, writable: true);
        if (writableKey is null || snapshot.SerializedData is null)
        {
            return;
        }

        object valueToWrite = snapshot.ValueKind switch
        {
            RegistryValueKind.DWord => int.Parse(snapshot.SerializedData, CultureInfo.InvariantCulture),
            RegistryValueKind.QWord => long.Parse(snapshot.SerializedData, CultureInfo.InvariantCulture),
            RegistryValueKind.Binary => Convert.FromBase64String(snapshot.SerializedData),
            RegistryValueKind.MultiString => JsonSerializer.Deserialize<string[]>(snapshot.SerializedData) ?? [],
            _ => snapshot.SerializedData
        };

        writableKey.SetValue(snapshot.ValueName, valueToWrite, snapshot.ValueKind);
    }
}
