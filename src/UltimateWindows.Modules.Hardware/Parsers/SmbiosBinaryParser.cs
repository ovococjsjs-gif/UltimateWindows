using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.Modules.Hardware.Parsers;

public sealed record SmbiosParsedData(
    MotherboardBiosInfo Motherboard,
    IReadOnlyList<MemoryModuleSlotInfo> MemorySlots);

/// <summary>
/// Декодер сырых таблиц SMBIOS / DMI (DMTF DSP0134) из буфера GetSystemFirmwareTable('RSMB').
/// Работает в чистом пользовательском режиме без драйверов ядра (WinRing0 не требуется).
/// </summary>
public static class SmbiosBinaryParser
{
    public static SmbiosParsedData ParseWindowsRawSmbios(ReadOnlySpan<byte> rawBuffer)
    {
        if (rawBuffer.Length < 8)
        {
            return CreateFallbackEmpty();
        }

        var major = rawBuffer[1];
        var minor = rawBuffer[2];
        var declaredLength = BinaryPrimitives.ReadUInt32LittleEndian(rawBuffer.Slice(4, 4));

        var tableData = rawBuffer[8..];
        if (declaredLength > 0 && declaredLength < tableData.Length)
        {
            tableData = tableData[..(int)declaredLength];
        }

        string biosVendor = "Unknown", biosVersion = "Unknown", biosDate = "Unknown";
        string sysManufacturer = "Unknown", sysProduct = "Unknown";
        string boardManufacturer = "Unknown", boardProduct = "Unknown", boardVersion = "";
        var memorySlots = new List<MemoryModuleSlotInfo>();

        var offset = 0;
        while (offset + 4 <= tableData.Length)
        {
            var type = tableData[offset];
            var formattedLength = tableData[offset + 1];

            if (formattedLength < 4 || offset + formattedLength > tableData.Length)
            {
                break;
            }

            var formattedSpan = tableData.Slice(offset, formattedLength);
            var stringsStart = offset + formattedLength;
            var (strings, nextStructureOffset) = ReadStringTable(tableData, stringsStart);

            if (type == 127) // End-of-Table
            {
                break;
            }

            switch (type)
            {
                case 0: // BIOS Information
                    biosVendor = GetString(strings, ReadByteOrZero(formattedSpan, 0x04), "Unknown");
                    biosVersion = GetString(strings, ReadByteOrZero(formattedSpan, 0x05), "Unknown");
                    biosDate = GetString(strings, ReadByteOrZero(formattedSpan, 0x08), "Unknown");
                    break;

                case 1: // System Information
                    sysManufacturer = GetString(strings, ReadByteOrZero(formattedSpan, 0x04), "Unknown");
                    sysProduct = GetString(strings, ReadByteOrZero(formattedSpan, 0x05), "Unknown");
                    break;

                case 2: // Baseboard (Motherboard) Information
                    boardManufacturer = GetString(strings, ReadByteOrZero(formattedSpan, 0x04), "Unknown");
                    boardProduct = GetString(strings, ReadByteOrZero(formattedSpan, 0x05), "Unknown");
                    boardVersion = GetString(strings, ReadByteOrZero(formattedSpan, 0x06), "");
                    break;

                case 17: // Memory Device (DIMM Slot)
                    memorySlots.Add(ParseMemoryDevice(formattedSpan, strings));
                    break;
            }

            offset = nextStructureOffset;
        }

        if (boardManufacturer == "Unknown" && sysManufacturer != "Unknown")
        {
            boardManufacturer = sysManufacturer;
        }

        if (boardProduct == "Unknown" && sysProduct != "Unknown")
        {
            boardProduct = sysProduct;
        }

        var mb = new MotherboardBiosInfo(
            BoardManufacturer: boardManufacturer,
            BoardProduct: boardProduct,
            BoardVersion: boardVersion,
            BiosVendor: biosVendor,
            BiosVersion: biosVersion,
            BiosReleaseDate: biosDate,
            SystemManufacturer: sysManufacturer,
            SystemProductName: sysProduct,
            SmbiosMajorVersion: major,
            SmbiosMinorVersion: minor);

        return new SmbiosParsedData(mb, memorySlots);
    }

    /// <summary>
    /// Определяет, работает ли подсистема памяти в двух- или многоканальном режиме на основе заполненных слотов SMBIOS.
    /// </summary>
    public static bool InferMultiChannelTopology(IReadOnlyList<MemoryModuleSlotInfo> slots)
    {
        var populated = slots.Where(s => s.IsPopulated).ToList();
        if (populated.Count < 2)
        {
            return false;
        }

        // Проверяем метки каналов в DeviceLocator / BankLocator (например, ChannelA/ChannelB, DIMM_A2/DIMM_B2, Controller0/Controller1)
        var distinctChannels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var mod in populated)
        {
            var combined = $"{mod.BankLocator} {mod.DeviceLocator}".ToUpperInvariant();
            if (combined.Contains("CHA") || combined.Contains("CHANNEL A") || combined.Contains("CHANNEL-A") ||
                combined.Contains("DIMM_A") || combined.Contains("DIMMA") || combined.Contains("A1") || combined.Contains("A2"))
            {
                distinctChannels.Add("A");
            }
            else if (combined.Contains("CHB") || combined.Contains("CHANNEL B") || combined.Contains("CHANNEL-B") ||
                     combined.Contains("DIMM_B") || combined.Contains("DIMMB") || combined.Contains("B1") || combined.Contains("B2"))
            {
                distinctChannels.Add("B");
            }
            else if (combined.Contains("CHC") || combined.Contains("CHANNEL C") || combined.Contains("C1") || combined.Contains("C2"))
            {
                distinctChannels.Add("C");
            }
            else if (combined.Contains("CHD") || combined.Contains("CHANNEL D") || combined.Contains("D1") || combined.Contains("D2"))
            {
                distinctChannels.Add("D");
            }
        }

        if (distinctChannels.Count >= 2)
        {
            return true;
        }

        if (distinctChannels.Count == 1)
        {
            // Обе планки явно воткнуты в один и тот же канал (например, DIMM_A1 + DIMM_A2)!
            return false;
        }

        // Если OEM-прошивка называет слоты просто Slot 0 / Slot 1 в ноутбуке с 2 слотами — при 2 равных планках активен двухканал
        return slots.Count == 2 && populated.Count == 2;
    }

    private static MemoryModuleSlotInfo ParseMemoryDevice(ReadOnlySpan<byte> formatted, List<string> strings)
    {
        var rawSize = ReadUInt16OrZero(formatted, 0x0C);
        long capacityBytes = 0;

        if (rawSize == 0x7FFF && formatted.Length >= 0x20)
        {
            var extSizeMib = BinaryPrimitives.ReadUInt32LittleEndian(formatted.Slice(0x1C, 4)) & 0x7FFF_FFFFu;
            capacityBytes = (long)extSizeMib * 1024L * 1024L;
        }
        else if (rawSize is not 0 and not 0xFFFF)
        {
            capacityBytes = (rawSize & 0x8000) != 0
                ? (rawSize & 0x7FFF) * 1024L
                : rawSize * 1024L * 1024L;
        }

        var devLocator = GetString(strings, ReadByteOrZero(formatted, 0x10), "DIMM");
        var bankLocator = GetString(strings, ReadByteOrZero(formatted, 0x11), "");
        var memTypeCode = ReadByteOrZero(formatted, 0x12);
        var memTypeName = DecodeMemoryType(memTypeCode);

        var ratedSpeed = (int)ReadUInt16OrZero(formatted, 0x15);
        var configuredSpeed = formatted.Length >= 0x22
            ? (int)ReadUInt16OrZero(formatted, 0x20)
            : ratedSpeed;

        if (configuredSpeed == 0)
        {
            configuredSpeed = ratedSpeed;
        }

        var manufacturer = GetString(strings, ReadByteOrZero(formatted, 0x17), "").Trim();
        var partNumber = GetString(strings, ReadByteOrZero(formatted, 0x1A), "").Trim();

        return new MemoryModuleSlotInfo(
            DeviceLocator: devLocator,
            BankLocator: bankLocator,
            MemoryType: memTypeName,
            CapacityBytes: capacityBytes,
            RatedSpeedMtPerSec: ratedSpeed,
            ConfiguredSpeedMtPerSec: configuredSpeed,
            Manufacturer: manufacturer,
            PartNumber: partNumber);
    }

    private static string DecodeMemoryType(byte code) => code switch
    {
        0x18 => "DDR3",
        0x1A => "DDR4",
        0x1E => "LPDDR4",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        _ => "DRAM"
    };

    private static (List<string> Strings, int NextOffset) ReadStringTable(ReadOnlySpan<byte> table, int start)
    {
        var list = new List<string>();
        var pos = start;

        if (pos + 1 < table.Length && table[pos] == 0 && table[pos + 1] == 0)
        {
            return (list, pos + 2);
        }

        while (pos < table.Length)
        {
            if (table[pos] == 0)
            {
                pos++;
                break;
            }

            var end = pos;
            while (end < table.Length && table[end] != 0)
            {
                end++;
            }

            var str = Encoding.UTF8.GetString(table.Slice(pos, end - pos)).Trim();
            list.Add(str);

            pos = end + 1;
        }

        return (list, Math.Min(pos, table.Length));
    }

    private static string GetString(List<string> strings, byte oneBasedIndex, string fallback)
    {
        if (oneBasedIndex == 0 || oneBasedIndex > strings.Count)
        {
            return fallback;
        }

        var val = strings[oneBasedIndex - 1];
        return string.IsNullOrWhiteSpace(val) ? fallback : val;
    }

    private static byte ReadByteOrZero(ReadOnlySpan<byte> span, int offset)
        => offset < span.Length ? span[offset] : (byte)0;

    private static ushort ReadUInt16OrZero(ReadOnlySpan<byte> span, int offset)
        => offset + 2 <= span.Length ? BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset, 2)) : (ushort)0;

    private static SmbiosParsedData CreateFallbackEmpty() => new(
        new MotherboardBiosInfo("Unknown", "Unknown", "", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", 0, 0),
        Array.Empty<MemoryModuleSlotInfo>());
}
