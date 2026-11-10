namespace UltimateWindows.Core.Models;

/// <summary>
/// Политика не засоряющего систему хранилища откатов и карантина (Zero-Bloat Vault).
/// </summary>
public sealed record VaultQuotaPolicy
{
    public const long Megabyte = 1024L * 1024L;
    public const long Gigabyte = 1024L * Megabyte;

    /// <summary>
    /// Максимальный потолок хранилища в байтах (по умолчанию 250 МБ).
    /// </summary>
    public long MaxVaultBytes { get; init; } = 250 * Megabyte;

    /// <summary>
    /// Минимальный гарантированный порог (32 МБ) даже на почти заполненных дисках.
    /// </summary>
    public long MinFloorBytes { get; init; } = 32 * Megabyte;

    /// <summary>
    /// Максимальная доля от свободного места на диске (по умолчанию 0.5% = 0.005).
    /// </summary>
    public double MaxFreeSpaceRatio { get; init; } = 0.005;

    /// <summary>
    /// Срок хранения незакрепленных файловых блобов в карантине (по умолчанию 14 дней).
    /// Записи отката реестра весят килобайты и сохраняются до ручной очистки.
    /// </summary>
    public int FileBlobRetentionDays { get; init; } = 14;

    /// <summary>
    /// Минимальный интервал между созданием системных точек восстановления VSS (по умолчанию 24 часа),
    /// чтобы не раздувать System Volume Information.
    /// </summary>
    public int RestorePointCooldownHours { get; init; } = 24;

    /// <summary>
    /// Вычисляет реальный допустимый бюджет диска с учетом свободного места на томе.
    /// </summary>
    public long ComputeEffectiveLimitBytes(long availableFreeSpaceBytes)
    {
        if (availableFreeSpaceBytes <= 0)
        {
            return Math.Min(MaxVaultBytes, MinFloorBytes);
        }

        var dynamicByFreeSpace = (long)(availableFreeSpaceBytes * MaxFreeSpaceRatio);
        var boundedDynamic = Math.Max(MinFloorBytes, dynamicByFreeSpace);
        return Math.Min(MaxVaultBytes, boundedDynamic);
    }
}

/// <summary>
/// Актуальная статистика расхода дискового пространства хранилищем откатов.
/// </summary>
public sealed record VaultStorageStats(
    long DatabaseBytes,
    long BlobBytes,
    long EffectiveLimitBytes,
    int BlobCount,
    int ActiveTransactionCount,
    int RevertedTransactionCount)
{
    public long TotalUsedBytes => DatabaseBytes + BlobBytes;

    public double UsagePercentage =>
        EffectiveLimitBytes <= 0
            ? 0.0
            : Math.Clamp((double)TotalUsedBytes / EffectiveLimitBytes * 100.0, 0.0, 100.0);

    public string FormattedUsage =>
        $"{ByteFormatter.Format(TotalUsedBytes)} из {ByteFormatter.Format(EffectiveLimitBytes)}";
}

/// <summary>
/// Утилита человекопонятного форматирования размеров для дружелюбного интерфейса.
/// </summary>
public static class ByteFormatter
{
    public static string Format(long bytes)
    {
        if (bytes < 1024)
            return $"{bytes} Б";
        if (bytes < 1024 * 1024)
            return $"{bytes / 1024.0:F1} КБ";
        if (bytes < 1024L * 1024L * 1024L)
            return $"{bytes / (1024.0 * 1024.0):F1} МБ";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} ГБ";
    }
}
