using System.Buffers.Binary;
using System.Text;
using UltimateWindows.Modules.Repair.Catalog;
using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.PeDoctor;

/// <summary>
/// Чистый бинарный анализатор Portable Executable (.exe / .dll):
/// читает заголовки MZ/COFF/OptionalHeader, таблицу секций, таблицу импорта IMAGE_IMPORT_DESCRIPTOR
/// и безошибочно выявляет причину ошибки 0xC000007B (конфликт разрядности x86/x64) и отсутствующие пакеты сред выполнения.
/// </summary>
public sealed class BinaryPeDependencyDoctor
{
    private const ushort DosMagicMz = 0x5A4D;      // 'MZ'
    private const uint PeSignature = 0x00004550;   // 'PE\0\0'
    private const ushort MachineI386 = 0x014C;
    private const ushort MachineAmd64 = 0x8664;
    private const ushort MachineArm64 = 0xAA64;
    private const ushort OptionalMagicPe32 = 0x010B;
    private const ushort OptionalMagicPe32Plus = 0x020B;

    private readonly record struct SectionSlice(
        uint VirtualSize,
        uint VirtualAddress,
        uint SizeOfRawData,
        uint PointerToRawData);

    /// <summary>
    /// Разбирает бинарный буфер PE-файла (.exe или .dll) без его загрузки или запуска в ОС.
    /// </summary>
    public static PeBinaryInspectionResult ParsePeBytes(ReadOnlySpan<byte> data, string sourcePath = "<memory>")
    {
        if (data.Length < 0x40)
        {
            return new PeBinaryInspectionResult(sourcePath, false, PeArchitecture.Unknown, false, 0, [], "Файл слишком мал для заголовка MZ.");
        }

        var mz = BinaryPrimitives.ReadUInt16LittleEndian(data[..2]);
        if (mz != DosMagicMz)
        {
            return new PeBinaryInspectionResult(sourcePath, false, PeArchitecture.Unknown, false, 0, [], "Отсутствует сигнатура исполняемого файла 'MZ'.");
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3C, 4));
        if (peOffset < 0x40 || peOffset + 24 > data.Length)
        {
            return new PeBinaryInspectionResult(sourcePath, false, PeArchitecture.Unknown, false, 0, [], "Некорректное смещение заголовка PE (e_lfanew).");
        }

        var peSig = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(peOffset, 4));
        if (peSig != PeSignature)
        {
            return new PeBinaryInspectionResult(sourcePath, false, PeArchitecture.Unknown, false, 0, [], "Отсутствует сигнатура 'PE\\0\\0'.");
        }

        var coffOffset = peOffset + 4;
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coffOffset, 2));
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coffOffset + 2, 2));
        var sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coffOffset + 16, 2));

        var arch = machine switch
        {
            MachineI386 => PeArchitecture.X86,
            MachineAmd64 => PeArchitecture.X64,
            MachineArm64 => PeArchitecture.Arm64,
            _ => PeArchitecture.Unknown
        };

        var optionalOffset = coffOffset + 20;
        if (sizeOfOptionalHeader < 24 || optionalOffset + sizeOfOptionalHeader > data.Length)
        {
            return new PeBinaryInspectionResult(sourcePath, false, arch, false, 0, [], "Поврежден Optional Header.");
        }

        var optMagic = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optionalOffset, 2));
        var isPe32Plus = optMagic == OptionalMagicPe32Plus;
        if (optMagic != OptionalMagicPe32 && !isPe32Plus)
        {
            return new PeBinaryInspectionResult(sourcePath, false, arch, false, 0, [], $"Неизвестный формат Optional Header (0x{optMagic:X4}).");
        }

        var subsystem = sizeOfOptionalHeader >= 70
            ? BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optionalOffset + 68, 2))
            : (ushort)0;

        var dataDirStartInOptional = isPe32Plus ? 112 : 96;
        uint importTableRva = 0;

        // DataDirectory[1] = IMAGE_DIRECTORY_ENTRY_IMPORT (каждая запись 8 байт: RVA + Size)
        if (sizeOfOptionalHeader >= dataDirStartInOptional + 16)
        {
            var numberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(optionalOffset + dataDirStartInOptional - 4, 4));
            if (numberOfRvaAndSizes >= 2)
            {
                var importDirOffset = optionalOffset + dataDirStartInOptional + 8;
                importTableRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importDirOffset, 4));
            }
        }

        // Читаем таблицу секций (по 40 байт на секцию сразу после Optional Header)
        var sectionsOffset = optionalOffset + sizeOfOptionalHeader;
        if (sectionsOffset + (numberOfSections * 40) > data.Length)
        {
            return new PeBinaryInspectionResult(sourcePath, true, arch, isPe32Plus, subsystem, []);
        }

        var sections = new SectionSlice[numberOfSections];
        for (int i = 0; i < numberOfSections; i++)
        {
            var sec = data.Slice(sectionsOffset + (i * 40), 40);
            sections[i] = new SectionSlice(
                VirtualSize: BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(8, 4)),
                VirtualAddress: BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(12, 4)),
                SizeOfRawData: BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(16, 4)),
                PointerToRawData: BinaryPrimitives.ReadUInt32LittleEndian(sec.Slice(20, 4)));
        }

        var imports = new List<string>();
        var seenImports = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (importTableRva != 0 && TryMapRvaToFileOffset(importTableRva, sections, data.Length, out var importFileOffset))
        {
            // Читаем массив IMAGE_IMPORT_DESCRIPTOR (по 20 байт до нулевого дескриптора, максимум 512 библиотек для защиты от битых заголовков)
            var cursor = importFileOffset;
            for (int guard = 0; guard < 512 && cursor + 20 <= data.Length; guard++, cursor += 20)
            {
                var desc = data.Slice(cursor, 20);
                var origFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc[..4]);
                var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(desc.Slice(12, 4));
                var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc.Slice(16, 4));

                if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                {
                    break;
                }

                if (nameRva != 0 &&
                    TryMapRvaToFileOffset(nameRva, sections, data.Length, out var nameFileOffset) &&
                    TryReadNullTerminatedAscii(data, nameFileOffset, maxBytes: 260, out var dllName) &&
                    !string.IsNullOrWhiteSpace(dllName) &&
                    seenImports.Add(dllName))
                {
                    imports.Add(dllName);
                }
            }
        }

        return new PeBinaryInspectionResult(sourcePath, true, arch, isPe32Plus, subsystem, imports);
    }

    public PeBinaryInspectionResult InspectFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new PeBinaryInspectionResult(filePath ?? "", false, PeArchitecture.Unknown, false, 0, [], "Файл не найден на диске.");
        }

        // Читаем весь файл, если он <= 32 МБ; для огромных игровых .exe читаем с полным маппингом потоком при необходимости
        var fi = new FileInfo(filePath);
        if (fi.Length <= 32 * 1024 * 1024)
        {
            var bytes = File.ReadAllBytes(filePath);
            return ParsePeBytes(bytes, filePath);
        }

        // Для очень крупных исполняемых файлов (>32 МБ) читаем буфер до 64 МБ, где почти всегда находятся таблицы импорта
        var cap = (int)Math.Min(fi.Length, 64L * 1024 * 1024);
        var buf = new byte[cap];
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var read = fs.ReadAtLeast(buf, buf.Length, throwOnEndOfStream: false);
        return ParsePeBytes(buf.AsSpan(0, read), filePath);
    }

    /// <summary>
    /// Проводит полную диагностику проблемного .exe файла:
    /// проверяет каждую импортируемую DLL в папке программы и соответствующем системном каталоге (System32 vs SysWOW64),
    /// выявляет причину ошибки 0xC000007B и формирует список официальных пакетов Microsoft для автоматического лечения.
    /// </summary>
    public ExecutableDiagnosisReport DiagnoseExecutable(
        string executablePath,
        string system64Directory,
        string sysWow64Directory)
    {
        var exeHeader = InspectFile(executablePath);
        if (!exeHeader.IsValidPeFile)
        {
            return new ExecutableDiagnosisReport(
                TargetExecutablePath: executablePath,
                BinaryHeader: exeHeader,
                IsHealthy: false,
                Has0xC000007BConflict: false,
                HeadlineVerdict: $"Файл не является корректным приложением Windows: {exeHeader.ParseError}",
                TotalDirectImportsCount: 0,
                Issues: [],
                RecommendedPackages: []);
        }

        var appDir = Path.GetDirectoryName(Path.GetFullPath(executablePath)) ?? "";
        var expectedSysDir = exeHeader.Architecture == PeArchitecture.X86 && !string.IsNullOrWhiteSpace(sysWow64Directory)
            ? sysWow64Directory
            : system64Directory;

        var issues = new List<PeDependencyIssue>();
        var recommendedByKey = new Dictionary<string, OfficialRuntimePackage>(StringComparer.OrdinalIgnoreCase);

        foreach (var dllName in exeHeader.ImportedDllNames)
        {
            if (OfficialRuntimeCatalog.IsVirtualWindowsApiSetContract(dllName))
            {
                continue;
            }

            var safeFileName = Path.GetFileName(dllName);
            var localCandidate = !string.IsNullOrWhiteSpace(appDir) ? Path.Combine(appDir, safeFileName) : "";
            var sysCandidate = !string.IsNullOrWhiteSpace(expectedSysDir) ? Path.Combine(expectedSysDir, safeFileName) : "";

            string? resolvedPath = null;
            if (!string.IsNullOrWhiteSpace(localCandidate) && File.Exists(localCandidate))
            {
                resolvedPath = localCandidate;
            }
            else if (!string.IsNullOrWhiteSpace(sysCandidate) && File.Exists(sysCandidate))
            {
                resolvedPath = sysCandidate;
            }

            if (resolvedPath is not null)
            {
                var dllHeader = InspectFile(resolvedPath);
                if (dllHeader.IsValidPeFile &&
                    dllHeader.Architecture != PeArchitecture.Unknown &&
                    exeHeader.Architecture != PeArchitecture.Unknown &&
                    dllHeader.Architecture != exeHeader.Architecture)
                {
                    var pkg = OfficialRuntimeCatalog.FindMatchingPackage(safeFileName, exeHeader.Architecture);
                    if (pkg is not null)
                    {
                        recommendedByKey[pkg.PackageKey] = pkg;
                    }

                    issues.Add(new PeDependencyIssue(
                        Kind: DependencyIssueKind.ArchitectureMismatch0xC000007B,
                        ImportedDllName: safeFileName,
                        ResolvedFilePath: resolvedPath,
                        ActualDllArchitecture: dllHeader.Architecture,
                        SimpleExplanation:
                            $"Найдена точная причина ошибки 0xC000007B! Программа ({exeHeader.ArchitectureDisplay}) пытается загрузить библиотеку «{safeFileName}» другой разрядности ({dllHeader.ArchitectureDisplay}).",
                        ExpertTechnicalDetails:
                            $"STATUS_INVALID_IMAGE_FORMAT (0xC000007B): {executablePath} [{exeHeader.Architecture}] -> {resolvedPath} [{dllHeader.Architecture}]. Поместите конфликтный локальный файл в карантин и установите официальный пакет.",
                        RecommendedPackage: pkg));
                }

                continue;
            }

            // Библиотека не найдена ни рядом с .exe, ни в системном каталоге нужной разрядности
            var officialPkg = OfficialRuntimeCatalog.FindMatchingPackage(safeFileName, exeHeader.Architecture);
            if (officialPkg is not null)
            {
                recommendedByKey[officialPkg.PackageKey] = officialPkg;
                issues.Add(new PeDependencyIssue(
                    Kind: DependencyIssueKind.MissingOfficialRuntimeDll,
                    ImportedDllName: safeFileName,
                    ResolvedFilePath: null,
                    ActualDllArchitecture: null,
                    SimpleExplanation:
                        $"Отсутствует системная библиотека «{safeFileName}». Лечится установкой официального пакета «{officialPkg.FriendlyName}» (не скачивайте одиночный DLL с сайтов!).",
                    ExpertTechnicalDetails:
                        $"Не найдена в '{appDir}' и '{expectedSysDir}'. Пакет: {officialPkg.WingetPackageId} ({officialPkg.ArchitectureBadge}).",
                    RecommendedPackage: officialPkg));
            }
            else if (!IsCoreWindowsOsDll(safeFileName))
            {
                issues.Add(new PeDependencyIssue(
                    Kind: DependencyIssueKind.MissingCustomApplicationDll,
                    ImportedDllName: safeFileName,
                    ResolvedFilePath: null,
                    ActualDllArchitecture: null,
                    SimpleExplanation:
                        $"В папке программы отсутствует собственный файл «{safeFileName}». Проверьте целостность файлов игры/программы в лаунчере или переустановите её.",
                    ExpertTechnicalDetails:
                        $"Внутренняя зависимость '{safeFileName}' не входит в стандартные пакеты Microsoft и отсутствует в '{appDir}'.",
                    RecommendedPackage: null));
            }
        }

        var has07b = issues.Any(i => i.Kind == DependencyIssueKind.ArchitectureMismatch0xC000007B);
        var isHealthy = issues.Count == 0;

        string headline;
        if (isHealthy)
        {
            headline = $"✅ Все зависимости ({exeHeader.ImportedDllNames.Count} библиотек) в полном порядке и совпадают по разрядности ({exeHeader.ArchitectureDisplay}).";
        }
        else if (has07b)
        {
            headline = $"🚨 Обнаружен конфликт разрядности 0xC000007B! Проблемных библиотек: {issues.Count}. Доступно безопасное лечение.";
        }
        else
        {
            headline = $"⚠️ Найдено отсутствующих библиотек: {issues.Count} (подобрано официальных пакетов Microsoft: {recommendedByKey.Count}).";
        }

        return new ExecutableDiagnosisReport(
            TargetExecutablePath: executablePath,
            BinaryHeader: exeHeader,
            IsHealthy: isHealthy,
            Has0xC000007BConflict: has07b,
            HeadlineVerdict: headline,
            TotalDirectImportsCount: exeHeader.ImportedDllNames.Count,
            Issues: issues,
            RecommendedPackages: recommendedByKey.Values.ToList());
    }

    private static bool TryMapRvaToFileOffset(
        uint rva,
        ReadOnlySpan<SectionSlice> sections,
        int fileLength,
        out int fileOffset)
    {
        foreach (var sec in sections)
        {
            var spanSize = Math.Max(sec.VirtualSize, sec.SizeOfRawData);
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + spanSize)
            {
                var delta = rva - sec.VirtualAddress;
                if (delta < sec.SizeOfRawData)
                {
                    var candidate = (long)sec.PointerToRawData + delta;
                    if (candidate >= 0 && candidate < fileLength)
                    {
                        fileOffset = (int)candidate;
                        return true;
                    }
                }
            }
        }

        // Резерв для заголовков до первой секции
        if (rva < fileLength && sections.Length == 0)
        {
            fileOffset = (int)rva;
            return true;
        }

        fileOffset = 0;
        return false;
    }

    private static bool TryReadNullTerminatedAscii(
        ReadOnlySpan<byte> data,
        int offset,
        int maxBytes,
        out string result)
    {
        result = "";
        if (offset < 0 || offset >= data.Length)
        {
            return false;
        }

        var limit = Math.Min(data.Length - offset, maxBytes);
        var slice = data.Slice(offset, limit);
        var zeroIdx = slice.IndexOf((byte)0);
        if (zeroIdx <= 0)
        {
            return false;
        }

        result = Encoding.ASCII.GetString(slice[..zeroIdx]);
        return true;
    }

    private static bool IsCoreWindowsOsDll(string lowerOrMixedDllName)
    {
        var lower = lowerOrMixedDllName.ToLowerInvariant();
        return lower is
            "kernel32.dll" or "kernelbase.dll" or "ntdll.dll" or "user32.dll" or "gdi32.dll" or
            "advapi32.dll" or "shell32.dll" or "ole32.dll" or "oleaut32.dll" or "combase.dll" or
            "rpcrt4.dll" or "sechost.dll" or "msvcrt.dll" or "ucrtbase.dll" or "ws2_32.dll" or
            "winmm.dll" or "imm32.dll" or "crypt32.dll" or "bcrypt.dll" or "shlwapi.dll" or
            "version.dll" or "setupapi.dll" or "cfgmgr32.dll" or "dwmapi.dll" or "uxtheme.dll" or
            "comdlg32.dll" or "comctl32.dll" or "dxgi.dll" or "d3d11.dll" or "d3d12.dll" or "d3d9.dll" or
            "opengl32.dll" or "iphlpapi.dll" or "winhttp.dll" or "wininet.dll" or "dbghelp.dll";
    }
}
