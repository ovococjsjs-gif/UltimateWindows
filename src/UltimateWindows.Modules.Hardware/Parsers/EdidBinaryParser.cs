using System.Buffers.Binary;
using System.Text;

namespace UltimateWindows.Modules.Hardware.Parsers;

public sealed record EdidParsedProfile(
    string ManufacturerCode,
    string MonitorName,
    int? ManufactureYear,
    int PreferredWidthPx,
    int PreferredHeightPx,
    int EdidMaxRefreshHz,
    int? ColorBitDepth,
    double? DiagonalInches);

/// <summary>
/// Декодер 128/256-байтовых блоков VESA E-EDID 1.3/1.4 мониторов.
/// Извлекает реальное имя матрицы, диагональ, битность цвета и максимальную частоту обновления (Гц).
/// </summary>
public static class EdidBinaryParser
{
    private static readonly byte[] EdidHeader = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

    public static EdidParsedProfile? TryParse(ReadOnlySpan<byte> edid)
    {
        if (edid.Length < 128)
        {
            return null;
        }

        if (!edid[..8].SequenceEqual(EdidHeader))
        {
            return null;
        }

        // 1. 3-буквенный код производителя EISA PnP ID (Big-Endian в байтах 8..9)
        var mfgRaw = BinaryPrimitives.ReadUInt16BigEndian(edid.Slice(8, 2));
        var c1 = (char)('A' + ((mfgRaw >> 10) & 0x1F) - 1);
        var c2 = (char)('A' + ((mfgRaw >> 5) & 0x1F) - 1);
        var c3 = (char)('A' + (mfgRaw & 0x1F) - 1);
        var mfgCode = (IsUpperAscii(c1) && IsUpperAscii(c2) && IsUpperAscii(c3))
            ? new string([c1, c2, c3])
            : "PNP";

        // 2. Год выпуска
        int? year = edid[17] > 0 ? 1990 + edid[17] : null;

        // 3. Глубина цвета EDID 1.4 (если цифровой вход)
        int? bitDepth = null;
        var videoInput = edid[20];
        if ((videoInput & 0x80) != 0)
        {
            bitDepth = ((videoInput >> 4) & 0x07) switch
            {
                1 => 6,
                2 => 8,
                3 => 10,
                4 => 12,
                5 => 14,
                6 => 16,
                _ => null
            };
        }

        // 4. Физический размер экрана (см -> дюймы)
        double? diagonalInches = null;
        var widthCm = edid[21];
        var heightCm = edid[22];
        if (widthCm > 0 && heightCm > 0)
        {
            var diagCm = Math.Sqrt(widthCm * widthCm + heightCm * heightCm);
            diagonalInches = Math.Round(diagCm / 2.54, 1);
        }

        // 5. Обход четырех 18-байтовых дескрипторов (байты 54..125)
        var monitorName = "";
        var preferredW = 0;
        var preferredH = 0;
        var maxRefreshHz = 60;

        for (var i = 0; i < 4; i++)
        {
            var block = edid.Slice(54 + i * 18, 18);
            var pixelClock10Khz = BinaryPrimitives.ReadUInt16LittleEndian(block[..2]);

            if (pixelClock10Khz != 0)
            {
                // Detailed Timing Descriptor (DTD)
                var hActive = block[2] | ((block[4] >> 4) << 8);
                var hBlank = block[3] | ((block[4] & 0x0F) << 8);
                var vActive = block[5] | ((block[7] >> 4) << 8);
                var vBlank = block[6] | ((block[7] & 0x0F) << 8);

                if (preferredW == 0 && hActive > 0 && vActive > 0)
                {
                    preferredW = hActive;
                    preferredH = vActive;
                }

                var hTotal = hActive + hBlank;
                var vTotal = vActive + vBlank;
                if (hTotal > 0 && vTotal > 0)
                {
                    var hz = (int)Math.Round((pixelClock10Khz * 10_000.0) / ((double)hTotal * vTotal));
                    if (hz is >= 24 and <= 540 && hz > maxRefreshHz)
                    {
                        maxRefreshHz = hz;
                    }
                }
            }
            else if (block[2] == 0)
            {
                var tag = block[3];
                if (tag == 0xFC) // Monitor Name
                {
                    monitorName = Encoding.ASCII.GetString(block.Slice(5, 13))
                        .Split('\n', '\r', '\0')[0]
                        .Trim();
                }
                else if (tag == 0xFD) // Monitor Range Limits
                {
                    var vMaxOffset = (block[4] & 0x02) != 0 ? 255 : 0;
                    var rangeMaxHz = block[6] + vMaxOffset;
                    if (rangeMaxHz is >= 30 and <= 540 && rangeMaxHz > maxRefreshHz)
                    {
                        maxRefreshHz = rangeMaxHz;
                    }
                }
            }
        }

        if (string.IsNullOrWhiteSpace(monitorName))
        {
            monitorName = $"{mfgCode} Display";
        }

        return new EdidParsedProfile(
            ManufacturerCode: mfgCode,
            MonitorName: monitorName,
            ManufactureYear: year,
            PreferredWidthPx: preferredW,
            PreferredHeightPx: preferredH,
            EdidMaxRefreshHz: maxRefreshHz,
            ColorBitDepth: bitDepth,
            DiagonalInches: diagonalInches);
    }

    private static bool IsUpperAscii(char c) => c is >= 'A' and <= 'Z';
}
