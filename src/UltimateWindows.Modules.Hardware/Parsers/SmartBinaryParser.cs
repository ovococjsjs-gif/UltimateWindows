using System.Buffers.Binary;

namespace UltimateWindows.Modules.Hardware.Parsers;

public sealed record NvmeSmartMetrics(
    byte CriticalWarningFlags,
    int TemperatureC,
    int AvailableSparePercent,
    int AvailableSpareThresholdPercent,
    int RemainingLifePercent,
    double TotalHostReadsTb,
    double TotalBytesWrittenTb,
    long PowerCycles,
    long PowerOnHours,
    long UnsafeShutdowns,
    long MediaIntegrityErrors)
{
    public bool IsHealthy =>
        CriticalWarningFlags == 0 &&
        MediaIntegrityErrors == 0 &&
        AvailableSparePercent >= AvailableSpareThresholdPercent;
}

public sealed record AtaSmartMetrics(
    bool IsHealthy,
    int? TemperatureC,
    int? RemainingLifePercent,
    long? PowerOnHours,
    long? PowerCycles,
    long ReallocatedSectors,
    long PendingSectors,
    long UltraDmaCrcErrors,
    double? TotalBytesWrittenTb);

/// <summary>
/// Чистые бинарные декодеры S.M.A.R.T. для NVMe (Health Information Log Page 0x02) и SATA/ATA (512-байтовый блок атрибутов).
/// </summary>
public static class SmartBinaryParser
{
    /// <summary>
    /// Разбирает 512-байтовый буфер NVME_HEALTH_INFO_LOG (NVM Express Base Specification).
    /// </summary>
    public static NvmeSmartMetrics? TryParseNvmeHealthLog(ReadOnlySpan<byte> logPage)
    {
        if (logPage.Length < 176)
        {
            return null;
        }

        var criticalWarning = logPage[0];
        var tempKelvin = BinaryPrimitives.ReadUInt16LittleEndian(logPage.Slice(1, 2));
        var tempC = tempKelvin > 0 ? Math.Clamp((int)tempKelvin - 273, -40, 150) : 0;

        var availableSpare = Math.Clamp((int)logPage[3], 0, 100);
        var spareThreshold = Math.Clamp((int)logPage[4], 0, 100);
        var percentageUsed = (int)logPage[5];
        var remainingLife = Math.Clamp(100 - percentageUsed, 0, 100);

        // 1 Data Unit = 1000 * 512 = 512,000 байт (в спецификации NVMe TBW считается в десятичных ТБ = 10^12 байт)
        var unitsReadLow = BinaryPrimitives.ReadUInt64LittleEndian(logPage.Slice(32, 8));
        var unitsWrittenLow = BinaryPrimitives.ReadUInt64LittleEndian(logPage.Slice(48, 8));

        var hostReadsTb = Math.Round(unitsReadLow * 512_000.0 / 1_000_000_000_000.0, 2);
        var tbw = Math.Round(unitsWrittenLow * 512_000.0 / 1_000_000_000_000.0, 2);

        var powerCycles = (long)Math.Min(long.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(logPage.Slice(112, 8)));
        var powerOnHours = (long)Math.Min(long.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(logPage.Slice(128, 8)));
        var unsafeShutdowns = (long)Math.Min(long.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(logPage.Slice(144, 8)));
        var mediaErrors = (long)Math.Min(long.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(logPage.Slice(160, 8)));

        return new NvmeSmartMetrics(
            CriticalWarningFlags: criticalWarning,
            TemperatureC: tempC,
            AvailableSparePercent: availableSpare,
            AvailableSpareThresholdPercent: spareThreshold,
            RemainingLifePercent: remainingLife,
            TotalHostReadsTb: hostReadsTb,
            TotalBytesWrittenTb: tbw,
            PowerCycles: powerCycles,
            PowerOnHours: powerOnHours,
            UnsafeShutdowns: unsafeShutdowns,
            MediaIntegrityErrors: mediaErrors);
    }

    /// <summary>
    /// Разбирает 362/512-байтовую таблицу атрибутов ATA/SATA S.M.A.R.T. (30 слотов по 12 байт начиная со смещения 2).
    /// </summary>
    public static AtaSmartMetrics? TryParseAtaSmartSector(ReadOnlySpan<byte> sector)
    {
        if (sector.Length < 362)
        {
            return null;
        }

        int? tempC = null;
        int? lifePercent = null;
        long? poh = null;
        long? powerCycles = null;
        long reallocated = 0;
        long pending = 0;
        long crcErrors = 0;
        double? tbw = null;

        for (var i = 0; i < 30; i++)
        {
            var entry = sector.Slice(2 + i * 12, 12);
            var attrId = entry[0];
            if (attrId is 0 or 0xFF)
            {
                continue;
            }

            var normalizedValue = entry[3];
            var raw32 = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(5, 4));
            var raw48 = raw32 | ((ulong)BinaryPrimitives.ReadUInt16LittleEndian(entry.Slice(9, 2)) << 32);

            switch (attrId)
            {
                case 0x05: // Reallocated Sectors Count
                    reallocated = (long)raw48;
                    break;

                case 0x09: // Power-On Hours
                    poh = raw32 & 0x00FF_FFFF;
                    break;

                case 0x0C: // Power Cycle Count
                    powerCycles = raw32;
                    break;

                case 0xBE or 0xC2: // Airflow / HDA Temperature (младший байт содержит текущую температуру в °C!)
                    var candidateTemp = (int)entry[5];
                    if (candidateTemp is >= 0 and <= 115)
                    {
                        tempC = candidateTemp;
                    }
                    break;

                case 0xC5: // Current Pending Sector Count
                    pending = (long)raw48;
                    break;

                case 0xC7: // UltraDMA CRC Error Count (ошибки SATA-шлейфа / разъема)
                    crcErrors = raw32;
                    break;

                case 0xB1 or 0xE7 or 0xE9: // Wear Leveling / SSD Life Left
                    if (normalizedValue is >= 1 and <= 100)
                    {
                        lifePercent = normalizedValue;
                    }
                    break;

                case 0xF1: // Total LBAs Written (512 байт на LBA)
                    if (raw48 > 0)
                    {
                        tbw = Math.Round(raw48 * 512.0 / 1_000_000_000_000.0, 2);
                    }
                    break;
            }
        }

        var isHealthy = reallocated == 0 && pending == 0 && (lifePercent is null or >= 10);

        return new AtaSmartMetrics(
            IsHealthy: isHealthy,
            TemperatureC: tempC,
            RemainingLifePercent: lifePercent,
            PowerOnHours: poh,
            PowerCycles: powerCycles,
            ReallocatedSectors: reallocated,
            PendingSectors: pending,
            UltraDmaCrcErrors: crcErrors,
            TotalBytesWrittenTb: tbw);
    }
}
