using System.Buffers.Binary;
using System.Runtime.Intrinsics.X86;
using System.Text;

namespace UltimateWindows.Modules.Hardware.Probes;

public sealed record CpuIdDecodedIdentity(
    string Vendor,
    string BrandString,
    int Family,
    int Model,
    int Stepping,
    IReadOnlyList<string> InstructionSets);

/// <summary>
/// Безопасный декодер процессорных инструкций CPUID через штатные интринсики .NET 8 (X86Base.CpuId).
/// Не требует драйверов ядра и полностью совместим с Windows 11 HVCI / Core Isolation и античитами.
/// </summary>
public static class CpuIdProbe
{
    public static CpuIdDecodedIdentity QueryCurrentProcessor()
    {
        if (!X86Base.IsSupported)
        {
            return new CpuIdDecodedIdentity(
                Vendor: "ARM64 / Non-x86",
                BrandString: Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "ARM64 Processor",
                Family: 0,
                Model: 0,
                Stepping: 0,
                InstructionSets: ["NEON"]);
        }

        var (maxBasicLeaf, ebx0, ecx0, edx0) = X86Base.CpuId(0, 0);
        Span<byte> vendorBytes = stackalloc byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(vendorBytes[..4], ebx0);
        BinaryPrimitives.WriteInt32LittleEndian(vendorBytes.Slice(4, 4), edx0);
        BinaryPrimitives.WriteInt32LittleEndian(vendorBytes.Slice(8, 4), ecx0);
        var vendor = Encoding.ASCII.GetString(vendorBytes).Trim('\0', ' ');

        var family = 0;
        var model = 0;
        var stepping = 0;
        var features = new List<string>();

        if (maxBasicLeaf >= 1)
        {
            var (eax1, _, ecx1, edx1) = X86Base.CpuId(1, 0);
            stepping = eax1 & 0x0F;
            var baseModel = (eax1 >> 4) & 0x0F;
            var baseFamily = (eax1 >> 8) & 0x0F;
            var extModel = (eax1 >> 16) & 0x0F;
            var extFamily = (eax1 >> 20) & 0xFF;

            family = baseFamily == 0x0F ? baseFamily + extFamily : baseFamily;
            model = baseFamily is 0x06 or 0x0F ? baseModel | (extModel << 4) : baseModel;

            if ((edx1 & (1 << 25)) != 0) features.Add("SSE");
            if ((edx1 & (1 << 26)) != 0) features.Add("SSE2");
            if ((ecx1 & (1 << 0)) != 0) features.Add("SSE3");
            if ((ecx1 & (1 << 9)) != 0) features.Add("SSSE3");
            if ((ecx1 & (1 << 19)) != 0) features.Add("SSE4.1");
            if ((ecx1 & (1 << 20)) != 0) features.Add("SSE4.2");
            if ((ecx1 & (1 << 25)) != 0) features.Add("AES-NI");
            if ((ecx1 & (1 << 28)) != 0) features.Add("AVX");
            if ((ecx1 & (1 << 12)) != 0) features.Add("FMA3");
        }

        if (maxBasicLeaf >= 7)
        {
            var (_, ebx7, _, _) = X86Base.CpuId(7, 0);
            if ((ebx7 & (1 << 5)) != 0) features.Add("AVX2");
            if ((ebx7 & (1 << 8)) != 0) features.Add("BMI2");
            if ((ebx7 & (1 << 16)) != 0) features.Add("AVX-512F");
            if ((ebx7 & (1 << 29)) != 0) features.Add("SHA");
        }

        var brandString = ReadBrandStringOrFallback(vendor);

        return new CpuIdDecodedIdentity(
            Vendor: vendor,
            BrandString: brandString,
            Family: family,
            Model: model,
            Stepping: stepping,
            InstructionSets: features);
    }

    private static string ReadBrandStringOrFallback(string fallbackVendor)
    {
        var (maxExtSigned, _, _, _) = X86Base.CpuId(unchecked((int)0x80000000u), 0);
        var maxExt = unchecked((uint)maxExtSigned);
        if (maxExt < 0x80000004u)
        {
            return $"{fallbackVendor} Processor";
        }

        Span<byte> brandBytes = stackalloc byte[48];
        for (var i = 0; i < 3; i++)
        {
            var leaf = unchecked((int)(0x80000002u + (uint)i));
            var (a, b, c, d) = X86Base.CpuId(leaf, 0);
            var slice = brandBytes.Slice(i * 16, 16);
            BinaryPrimitives.WriteInt32LittleEndian(slice[..4], a);
            BinaryPrimitives.WriteInt32LittleEndian(slice.Slice(4, 4), b);
            BinaryPrimitives.WriteInt32LittleEndian(slice.Slice(8, 4), c);
            BinaryPrimitives.WriteInt32LittleEndian(slice.Slice(12, 4), d);
        }

        var raw = Encoding.ASCII.GetString(brandBytes).Trim('\0', ' ');
        // Схлопываем двойные пробелы, которые часто встречаются в строках старых процессоров Intel
        while (raw.Contains("  ", StringComparison.Ordinal))
        {
            raw = raw.Replace("  ", " ", StringComparison.Ordinal);
        }

        return string.IsNullOrWhiteSpace(raw) ? $"{fallbackVendor} Processor" : raw;
    }
}
