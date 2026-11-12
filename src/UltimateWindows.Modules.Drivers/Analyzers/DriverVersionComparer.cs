using System.Globalization;

namespace UltimateWindows.Modules.Drivers.Analyzers;

/// <summary>
/// Точное сравнение версий и дат драйверов Windows (форматы X.Y.Z.W и DriverVer=MM/DD/YYYY,X.Y.Z.W).
/// </summary>
public static class DriverVersionComparer
{
    private static readonly string[] DateFormats =
    [
        "yyyy-MM-dd",
        "MM/dd/yyyy",
        "M/d/yyyy",
        "dd.MM.yyyy",
        "yyyy/MM/dd"
    ];

    public static bool TryParseDriverVersion(string? rawVersion, out ulong packedVersion)
    {
        packedVersion = 0;
        if (string.IsNullOrWhiteSpace(rawVersion))
        {
            return false;
        }

        // Отрезаем возможные префиксы/суффиксы вроде "WHQL (2025-01-10)" или "10/15/2024 22.250.1.2"
        var token = rawVersion.Trim();
        var spaceIdx = token.LastIndexOf(' ');
        if (spaceIdx >= 0 && spaceIdx + 1 < token.Length && char.IsDigit(token[spaceIdx + 1]))
        {
            token = token[(spaceIdx + 1)..];
        }

        var parts = token.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2 || parts.Length > 4)
        {
            return false;
        }

        ushort[] nums = [0, 0, 0, 0];
        for (int i = 0; i < parts.Length; i++)
        {
            var clean = new string(parts[i].TakeWhile(char.IsDigit).ToArray());
            if (clean.Length == 0 || !uint.TryParse(clean, NumberStyles.None, CultureInfo.InvariantCulture, out var val))
            {
                return false;
            }

            nums[i] = (ushort)Math.Min(val, ushort.MaxValue);
        }

        packedVersion = ((ulong)nums[0] << 48) | ((ulong)nums[1] << 32) | ((ulong)nums[2] << 16) | nums[3];
        return packedVersion > 0;
    }

    public static DateTimeOffset? TryParseDriverDate(string? rawDate)
    {
        if (string.IsNullOrWhiteSpace(rawDate))
        {
            return null;
        }

        var cleaned = rawDate.Trim();
        if (DateTimeOffset.TryParseExact(
                cleaned,
                DateFormats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var exact))
        {
            return exact;
        }

        if (DateTimeOffset.TryParse(cleaned, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    public static string NormalizeDateDisplay(string? rawDate)
    {
        var dt = TryParseDriverDate(rawDate);
        return dt.HasValue ? dt.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : (rawDate?.Trim() ?? "");
    }

    /// <summary>
    /// Сравнивает две версии драйвера (&lt;0 если left старше right, 0 если равны, &gt;0 если left новее right).
    /// Сначала сравнивает 4-частный номер X.Y.Z.W, а при равенстве или отсутствии — дату выпуска.
    /// </summary>
    public static int Compare(string? leftVersion, string? leftDate, string? rightVersion, string? rightDate)
    {
        bool hasLeftVer = TryParseDriverVersion(leftVersion, out var lVer);
        bool hasRightVer = TryParseDriverVersion(rightVersion, out var rVer);

        if (hasLeftVer && hasRightVer && lVer != rVer)
        {
            return lVer.CompareTo(rVer);
        }

        var lDate = TryParseDriverDate(leftDate);
        var rDate = TryParseDriverDate(rightDate);
        if (lDate.HasValue && rDate.HasValue)
        {
            var dayCmp = lDate.Value.Date.CompareTo(rDate.Value.Date);
            if (dayCmp != 0)
            {
                return dayCmp;
            }
        }

        if (hasLeftVer != hasRightVer)
        {
            return hasLeftVer ? 1 : -1;
        }

        return string.Compare(leftVersion ?? "", rightVersion ?? "", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Разбирает строку INF-секции [Version] вида "DriverVer = 09/18/2025, 31.0.15.6094".
    /// </summary>
    public static (string Date, string Version) ParseInfDriverVerDirective(string? rawDirectiveValue)
    {
        if (string.IsNullOrWhiteSpace(rawDirectiveValue))
        {
            return ("", "");
        }

        var parts = rawDirectiveValue.Split(',', 2, StringSplitOptions.TrimEntries);
        var date = NormalizeDateDisplay(parts[0]);
        var ver = parts.Length > 1 ? parts[1].Split(';', 2)[0].Trim() : "";
        return (date, ver);
    }
}
