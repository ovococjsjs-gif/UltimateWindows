using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Core.Contracts;
using UltimateWindows.Core.Enums;
using UltimateWindows.Core.Models;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Safety.Services;
using UltimateWindows.Modules.Safety.Storage;
using UltimateWindows.NativeInterop.Optimizer;
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
/// <param name="CreatedKeyPath">
/// Самый верхний раздел, которого не было до изменения. При откате опустевшие разделы от <paramref name="SubKey"/>
/// до него включительно удаляются: откат убирает ровно то, что создало изменение.
/// </param>
public sealed record RegistryValueSnapshot(
    string Hive,
    string SubKey,
    string ValueName,
    bool ExistedBefore,
    RegistryValueKind ValueKind,
    string? SerializedData,
    string? CreatedKeyPath = null);

/// <summary>
/// Полноценный исполнитель откатов для Windows: восстанавливает значения реестра, типы запуска служб, задания планировщика, видеорежимы монитора, схемы питания и файлы из карантина.
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

        if (delta.TargetKind == StateTargetKind.WindowsService &&
            OperatingSystem.IsWindows() &&
            !string.IsNullOrWhiteSpace(delta.PreviousStateJson))
        {
            RestoreServiceStartup(delta);
            return;
        }

        if (delta.TargetKind == StateTargetKind.ScheduledTask &&
            OperatingSystem.IsWindows() &&
            !string.IsNullOrWhiteSpace(delta.PreviousStateJson))
        {
            RestoreScheduledTask(delta);
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

            if (string.Equals(delta.TargetPath, "HostsSabotageCleanup", StringComparison.OrdinalIgnoreCase))
            {
                using var doc = JsonDocument.Parse(delta.PreviousStateJson);
                var p = doc.RootElement.TryGetProperty("Path", out var pEl) ? pEl.GetString() : null;
                var c = doc.RootElement.TryGetProperty("Content", out var cEl) ? cEl.GetString() : null;
                if (!string.IsNullOrWhiteSpace(p) && c is not null)
                {
                    await File.WriteAllTextAsync(p, c, ct).ConfigureAwait(false);
                }

                return;
            }

            if (delta.TargetPath.StartsWith("DriverInfBackup:", StringComparison.OrdinalIgnoreCase))
            {
                using var doc = JsonDocument.Parse(delta.PreviousStateJson);
                var zipPath = doc.RootElement.TryGetProperty("RestoredArchivePath", out var zEl) ? zEl.GetString() : null;
                if (!string.IsNullOrWhiteSpace(zipPath) && File.Exists(zipPath))
                {
                    var unpackDir = Path.Combine(Path.GetTempPath(), "uw-drv-restore-" + Guid.NewGuid().ToString("N"));
                    try
                    {
                        ZipFile.ExtractToDirectory(zipPath, unpackDir, overwriteFiles: true);
                        foreach (var infPath in Directory.GetFiles(unpackDir, "*.inf", SearchOption.AllDirectories))
                        {
                            var psi = new ProcessStartInfo
                            {
                                FileName = Path.Combine(Environment.SystemDirectory, "pnputil.exe"),
                                CreateNoWindow = true,
                                UseShellExecute = false
                            };
                            psi.ArgumentList.Add("/add-driver");
                            psi.ArgumentList.Add(infPath);
                            psi.ArgumentList.Add("/install");
                            using var proc = Process.Start(psi);
                            if (proc is not null)
                            {
                                await proc.WaitForExitAsync(ct).ConfigureAwait(false);
                            }
                        }
                    }
                    finally
                    {
                        try { if (Directory.Exists(unpackDir)) Directory.Delete(unpackDir, true); } catch { }
                        try { File.Delete(zipPath); } catch { }
                    }
                }

                return;
            }
        }

        await base.ApplyRollbackDeltaAsync(delta, restoreBlobBytesAsync, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Возвращает службе прежний тип запуска. Если службу с тех пор удалили, возвращать нечего.
    /// </summary>
    private static void RestoreServiceStartup(StateDeltaRecord delta)
    {
        using var doc = JsonDocument.Parse(delta.PreviousStateJson!);
        var name = doc.RootElement.TryGetProperty("ServiceName", out var nameElement) ? nameElement.GetString() : delta.TargetPath;
        var startupText = doc.RootElement.TryGetProperty("Startup", out var startupElement) ? startupElement.GetString() : null;

        if (string.IsNullOrWhiteSpace(name) ||
            !Enum.TryParse<ServiceStartupMode>(startupText, ignoreCase: true, out var startup))
        {
            return;
        }

        var current = WindowsServiceControl.Query(name);
        if (current is null || current.Startup == startup)
        {
            return;
        }

        var result = WindowsServiceControl.SetStartup(name, startup);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Не удалось вернуть службе «{name}» тип запуска «{ServiceDisplay.GetTitle(startup)}»: {result.Error}.");
        }
    }

    /// <summary>
    /// Возвращает заданию планировщика прежнее состояние. Если задание с тех пор удалили, возвращать нечего.
    /// </summary>
    private static void RestoreScheduledTask(StateDeltaRecord delta)
    {
        using var doc = JsonDocument.Parse(delta.PreviousStateJson!);
        var path = doc.RootElement.TryGetProperty("TaskPath", out var pathElement) ? pathElement.GetString() : delta.TargetPath;
        if (string.IsNullOrWhiteSpace(path) ||
            !doc.RootElement.TryGetProperty("Enabled", out var enabledElement) ||
            (enabledElement.ValueKind != JsonValueKind.True && enabledElement.ValueKind != JsonValueKind.False))
        {
            return;
        }

        var enabled = enabledElement.GetBoolean();
        var current = WindowsTaskScheduler.Query([path]);
        if (!current.TryGetValue(path, out var snapshot) || snapshot.Enabled == enabled)
        {
            return;
        }

        var result = WindowsTaskScheduler.SetEnabled(path, enabled);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Не удалось вернуть задание «{path}» в состояние «{TweakScheduledTaskAction.FormatEnabled(enabled)}»: {result.Error}.");
        }
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
            using (var subKey = baseKey.OpenSubKey(snapshot.SubKey, writable: true))
            {
                subKey?.DeleteValue(snapshot.ValueName, throwOnMissingValue: false);
            }

            RemoveCreatedKeys(baseKey, snapshot.SubKey, snapshot.CreatedKeyPath);
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

    /// <summary>
    /// Удаляет разделы, созданные изменением: от самого глубокого вверх до <paramref name="createdKeyPath"/> включительно,
    /// и только пока раздел пуст. Раздел, в котором с тех пор появилось что-то ещё, остаётся.
    /// </summary>
    private static void RemoveCreatedKeys(RegistryKey baseKey, string subKeyPath, string? createdKeyPath)
    {
        if (string.IsNullOrWhiteSpace(createdKeyPath) ||
            !subKeyPath.StartsWith(createdKeyPath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var path = subKeyPath;
        while (path.Length >= createdKeyPath.Length)
        {
            try
            {
                using (var key = baseKey.OpenSubKey(path, writable: false))
                {
                    if (key is null)
                    {
                        // Раздела уже нет — проверяем его родителя
                    }
                    else if (key.ValueCount > 0 || key.SubKeyCount > 0)
                    {
                        return;
                    }
                }

                baseKey.DeleteSubKey(path, throwOnMissingSubKey: false);
            }
            catch (Exception)
            {
                return;
            }

            var separator = path.LastIndexOf('\\');
            if (path.Length == createdKeyPath.Length || separator <= 0)
            {
                return;
            }

            path = path[..separator];
        }
    }
}
