using System.Globalization;
using System.Text.Json;
using Microsoft.Win32;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Optimizer.Models;
using UltimateWindows.Modules.Security.Models;
using UltimateWindows.NativeInterop.Optimizer;
using UltimateWindows.NativeInterop.Restore;

namespace UltimateWindows.NativeInterop.SecurityHunter;

public sealed partial class WindowsSecurityPlatformBridge
{
    private const string FirewallRules = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    public override PreparedSecurityChange PreparePersistence(PersistenceAnomalyRecord record)
    {
        if (!record.CanRemediate) throw new InvalidOperationException("Запись не помечена для исправления.");
        var target = record.RemediationTarget;
        switch (record.RemediationKind)
        {
            case PersistenceRemediationKind.DeleteRegistryValue:
            case PersistenceRemediationKind.RestoreRegistryDefault:
            {
                var parts = target.Split('|');
                bool replace = record.RemediationKind == PersistenceRemediationKind.RestoreRegistryDefault;
                if (parts.Length != (replace ? 4 : 3)) throw new InvalidDataException("Неоднозначная цель в реестре.");
                object? replacement = null;
                RegistryValueKind? kind = null;
                if (replace)
                {
                    var spec = parts[3];
                    (replacement, kind) = spec switch
                    {
                        _ when spec.StartsWith("DWORD:", StringComparison.Ordinal) => ((object)int.Parse(spec[6..], CultureInfo.InvariantCulture), RegistryValueKind.DWord),
                        _ when spec.StartsWith("MULTI:", StringComparison.Ordinal) => (new[] { spec[6..] }, RegistryValueKind.MultiString),
                        _ => (spec, RegistryValueKind.String)
                    };
                }
                return ReviewValue($"Автозакрепление: {record.EntryName}", parts[0], parts[1], parts[2], record.PreviousValueSerialized, replacement, kind);
            }
            case PersistenceRemediationKind.DisableWindowsService:
            {
                var before = WindowsServiceControl.Query(target) ?? throw new IOException("Не удалось прочесть тип запуска службы.");
                if (before.Startup is not (ServiceStartupMode.Automatic or ServiceStartupMode.AutomaticDelayed or ServiceStartupMode.Manual))
                    throw new InvalidOperationException("Загрузочная, системная или уже отключённая служба не изменена.");
                return new($"Тип запуска службы {target}", StateTargetKind.WindowsService, target,
                    JsonSerializer.Serialize(new { ServiceName = target, Startup = before.Startup.ToString() }), token => Task.Run(() =>
                    {
                        // Не останавливаем работающую службу как скрытый побочный эффект смены типа запуска.
                        return WindowsServiceControl.Query(target) == before && WindowsServiceControl.SetStartup(target, ServiceStartupMode.Disabled).Succeeded &&
                               WindowsServiceControl.Query(target)?.Startup == ServiceStartupMode.Disabled;
                    }, token));
            }
            case PersistenceRemediationKind.DisableScheduledTask:
            {
                bool? Enabled() => WindowsTaskScheduler.Query([target]).TryGetValue(target, out var task) ? task.Enabled : null;
                if (Enabled() != true) throw new InvalidOperationException("Задача отсутствует, недоступна или уже отключена.");
                return new($"Отключение задачи {target}", StateTargetKind.ScheduledTask, target,
                    JsonSerializer.Serialize(new { TaskPath = target, Enabled = true }), token => Task.Run(() =>
                        Enabled() == true && WindowsTaskScheduler.SetEnabled(target, false).Succeeded && Enabled() == false, token));
            }
            default:
                // Путь/имя WMI, BITS, задачи или поддерева реестра не является полным снимком.
                throw new NotSupportedException($"«{record.EntryName}»: нет полного снимка для этого действия. Требуется ручная проверка.");
        }
    }

    public override PreparedSecurityChange PrepareFirewallRule(FirewallRuleAnomaly rule) =>
        ReviewValue($"Правило брандмауэра: {rule.DisplayName}", "HKLM", FirewallRules, rule.RuleId, rule.RawRegistryValue);

    public override PreparedSecurityChange PrepareSabotageRepair(OsSabotageFinding item) => item.Kind switch
    {
        OsSabotageKind.SecurityDomainsBlockedInHosts => ReviewedHostsRepair.Prepare(item.TargetDisplayPath),
        OsSabotageKind.FirewallOutboundSecurityBlock => ReviewValue(item.SimpleTitle, "HKLM", FirewallRules, item.ValueName, item.CurrentMaliciousValue),
        _ => ReviewValue(item.SimpleTitle, item.Hive, item.SubKeyPath, item.ValueName, item.CurrentMaliciousValue)
    };

    public override PreparedSecurityChange PrepareDefenderExclusion(DefenderExclusionFinding item)
    {
        if (item.IsPolicyEnforced) throw new InvalidOperationException("Исключение задано групповой политикой. Изменять его нужно в источнике политики.");
        if (!item.IsDangerousMinerExclusion) throw new InvalidOperationException("Исключение не отмечено как опасное.");
        var (section, parameter) = item.Kind switch
        {
            DefenderExclusionKind.Path => ("Paths", "ExclusionPath"), DefenderExclusionKind.Process => ("Processes", "ExclusionProcess"),
            DefenderExclusionKind.Extension => ("Extensions", "ExclusionExtension"), DefenderExclusionKind.IpAddress => ("IpAddresses", "ExclusionIpAddress"),
            _ => throw new NotSupportedException("Неизвестная категория исключения.")
        };
        var sub = @"SOFTWARE\Microsoft\Windows Defender\Exclusions\" + section;
        if (!string.Equals(item.RegistryPath, @"HKLM\" + sub, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Источник исключения изменился.");
        bool Present()
        {
            using var key = Registry.LocalMachine.OpenSubKey(sub) ?? throw new IOException("Источник исключений недоступен.");
            return key.GetValueNames().Contains(item.Value, StringComparer.OrdinalIgnoreCase);
        }
        if (!Present()) throw new InvalidOperationException("Исключение больше не найдено.");
        // Не восстанавливаем автоматически слепую зону антивируса и не меняем Tamper Protection.
        return new($"Исключение Defender: {item.Value}", StateTargetKind.JournalEntry, item.RegistryPath,
            JsonSerializer.Serialize(new { item.Kind, item.Value }), token => Task.Run(() =>
            Present() && RunShortPowerShell($"Remove-MpPreference -{parameter} '{item.Value.Replace("'", "''")}' -ErrorAction Stop", 6000) && !Present(), token));
    }

    private static PreparedSecurityChange ReviewValue(string label, string hiveLabel, string sub, string name,
        string? reviewedData, object? replacement = null, RegistryValueKind? replacementKind = null)
    {
        var (hive, view) = hiveLabel.ToUpperInvariant() switch
        {
            "HKCU" => (RegistryHive.CurrentUser, RegistryView.Default), "HKLM" => (RegistryHive.LocalMachine, RegistryView.Default),
            "HKLM32" => (RegistryHive.LocalMachine, RegistryView.Registry32), _ => throw new InvalidDataException("Неизвестная ветвь реестра.")
        };
        if (string.IsNullOrWhiteSpace(sub) || reviewedData is null) throw new InvalidDataException("Не указаны прежнее значение или ключ.");
        using var root = RegistryKey.OpenBaseKey(hive, view);
        using var key = root.OpenSubKey(sub) ?? throw new IOException("Проверенный ключ отсутствует.");
        var kind = key.GetValueKind(name);
        var previous = ReadRaw(key, name);
        if (previous is null || previous != reviewedData || previous.Length > 512 * 1024) throw new IOException("Значение изменилось или превышает лимит снимка.");
        var expected = replacement is null ? null : FormatRaw(replacement);
        if (kind == replacementKind && previous == expected) throw new InvalidOperationException("Значение уже исправлено.");
        var snapshot = new RegistryValueSnapshot(hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU", sub, name, true, kind, previous,
            OnlyRestoreIfAbsent: replacement is null, View: view, ExpectedKind: replacementKind, ExpectedData: expected);
        return new(label, StateTargetKind.RegistryValue, $@"{hiveLabel}\{sub}::{name}", JsonSerializer.Serialize(snapshot), token => Task.Run(() =>
        {
            using var currentRoot = RegistryKey.OpenBaseKey(hive, view);
            using var current = currentRoot.OpenSubKey(sub, writable: true);
            if (current is null || ReadRaw(current, name) != previous || current.GetValueKind(name) != kind) return false;
            if (replacement is null)
            {
                current.DeleteValue(name, throwOnMissingValue: true);
                return !current.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase);
            }
            current.SetValue(name, replacement, replacementKind!.Value);
            return current.GetValueKind(name) == replacementKind && ReadRaw(current, name) == expected;
        }, token));
    }

    private static string? ReadRaw(RegistryKey key, string name) => key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is { } val ? FormatRaw(val) : null;
    internal static string FormatRaw(object val) => val switch
    {
        string[] strings => JsonSerializer.Serialize(strings), byte[] bytes => Convert.ToBase64String(bytes),
        string str => str, int or long => Convert.ToString(val, CultureInfo.InvariantCulture)!, _ => throw new InvalidDataException("Тип значения не поддерживается.")
    };
}
