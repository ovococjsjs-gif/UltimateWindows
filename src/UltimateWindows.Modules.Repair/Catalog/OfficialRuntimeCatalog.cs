using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Catalog;

/// <summary>
/// Белый каталог официальных подписанных сред выполнения Microsoft / Khronos / OpenAL.
/// Полностью исключает опасное скачивание одиночных «левых» .dll файлов со сторонних сайтов.
/// </summary>
public static class OfficialRuntimeCatalog
{
    private static readonly IReadOnlyList<OfficialRuntimePackage> AllPackages =
    [
        new(
            PackageKey: "vcredist-2015-2022-x64",
            WingetPackageId: "Microsoft.VCRedist.2015+.x64",
            FriendlyName: "Microsoft Visual C++ 2015–2022 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower:
            [
                "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll",
                "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
                "concrt140.dll", "vcomp140.dll", "vcamp140.dll", "mfc140.dll", "mfc140u.dll",
                "mfcm140u.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll",
                "api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll"
            ]),

        new(
            PackageKey: "vcredist-2015-2022-x86",
            WingetPackageId: "Microsoft.VCRedist.2015+.x86",
            FriendlyName: "Microsoft Visual C++ 2015–2022 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower:
            [
                "vcruntime140.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
                "concrt140.dll", "vcomp140.dll", "vcamp140.dll", "mfc140.dll", "mfc140u.dll",
                "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll",
                "api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll"
            ]),

        new(
            PackageKey: "vcredist-2013-x64",
            WingetPackageId: "Microsoft.VCRedist.2013.x64",
            FriendlyName: "Microsoft Visual C++ 2013 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr120.dll", "msvcp120.dll", "vcomp120.dll", "mfc120.dll", "mfc120u.dll"]),

        new(
            PackageKey: "vcredist-2013-x86",
            WingetPackageId: "Microsoft.VCRedist.2013.x86",
            FriendlyName: "Microsoft Visual C++ 2013 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr120.dll", "msvcp120.dll", "vcomp120.dll", "mfc120.dll", "mfc120u.dll"]),

        new(
            PackageKey: "vcredist-2012-x64",
            WingetPackageId: "Microsoft.VCRedist.2012.x64",
            FriendlyName: "Microsoft Visual C++ 2012 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr110.dll", "msvcp110.dll", "vcomp110.dll", "mfc110u.dll"]),

        new(
            PackageKey: "vcredist-2012-x86",
            WingetPackageId: "Microsoft.VCRedist.2012.x86",
            FriendlyName: "Microsoft Visual C++ 2012 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr110.dll", "msvcp110.dll", "vcomp110.dll", "mfc110u.dll"]),

        new(
            PackageKey: "vcredist-2010-x64",
            WingetPackageId: "Microsoft.VCRedist.2010.x64",
            FriendlyName: "Microsoft Visual C++ 2010 SP1 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/q /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr100.dll", "msvcp100.dll", "vcomp100.dll", "mfc100u.dll"]),

        new(
            PackageKey: "vcredist-2010-x86",
            WingetPackageId: "Microsoft.VCRedist.2010.x86",
            FriendlyName: "Microsoft Visual C++ 2010 SP1 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/q /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr100.dll", "msvcp100.dll", "vcomp100.dll", "mfc100u.dll"]),

        new(
            PackageKey: "directx-june-2010",
            WingetPackageId: "Microsoft.DirectX",
            FriendlyName: "Microsoft DirectX End-User Runtimes (June 2010)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "/silent",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=35",
            ProvidedDllNamesLower:
            [
                "d3dx9_24.dll", "d3dx9_25.dll", "d3dx9_26.dll", "d3dx9_27.dll", "d3dx9_28.dll",
                "d3dx9_29.dll", "d3dx9_30.dll", "d3dx9_31.dll", "d3dx9_32.dll", "d3dx9_33.dll",
                "d3dx9_34.dll", "d3dx9_35.dll", "d3dx9_36.dll", "d3dx9_37.dll", "d3dx9_38.dll",
                "d3dx9_39.dll", "d3dx9_40.dll", "d3dx9_41.dll", "d3dx9_42.dll", "d3dx9_43.dll",
                "d3dx10_33.dll", "d3dx10_39.dll", "d3dx10_40.dll", "d3dx10_41.dll", "d3dx10_42.dll", "d3dx10_43.dll",
                "d3dx11_42.dll", "d3dx11_43.dll", "d3dcompiler_42.dll", "d3dcompiler_43.dll",
                "xinput1_1.dll", "xinput1_2.dll", "xinput1_3.dll", "x3daudio1_7.dll", "xapofx1_5.dll"
            ]),

        new(
            PackageKey: "dotnet-desktop-8-x64",
            WingetPackageId: "Microsoft.DotNet.DesktopRuntime.8",
            FriendlyName: "Microsoft .NET 8 Desktop Runtime",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://dotnet.microsoft.com/download/dotnet/8.0",
            ProvidedDllNamesLower: ["hostfxr.dll", "coreclr.dll", "hostpolicy.dll"]),

        new(
            PackageKey: "openal-runtime",
            WingetPackageId: "OpenAL.OpenAL",
            FriendlyName: "OpenAL Cross-Platform 3D Audio Runtime",
            PublisherName: "OpenAL / Creative Labs",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "/s",
            OfficialDownloadPageUrl: "https://www.openal.org/downloads/",
            ProvidedDllNamesLower: ["openal32.dll", "wrap_oal.dll"]),

        new(
            PackageKey: "xna-framework-40",
            WingetPackageId: "Microsoft.XNARedist",
            FriendlyName: "Microsoft XNA Framework Redistributable 4.0",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/qn /norestart",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=20914",
            ProvidedDllNamesLower: ["microsoft.xna.framework.dll"])
    ];

    public static IReadOnlyList<OfficialRuntimePackage> GetAllPackages() => AllPackages;

    /// <summary>
    /// Подбирает официальный пакет распространяемых компонентов по имени проблемной или отсутствующей DLL
    /// и требуемой разрядности целевого .exe файла.
    /// </summary>
    public static OfficialRuntimePackage? FindMatchingPackage(string dllName, PeArchitecture requiredArch)
    {
        if (string.IsNullOrWhiteSpace(dllName))
        {
            return null;
        }

        var normalized = Path.GetFileName(dllName.Trim()).ToLowerInvariant();

        // Специальное правило для всех api-ms-win-crt-*.dll -> пакет VC++ 2015-2022 нужной разрядности
        if (normalized.StartsWith("api-ms-win-crt-", StringComparison.Ordinal))
        {
            return AllPackages.FirstOrDefault(p =>
                p.PackageKey.StartsWith("vcredist-2015-2022", StringComparison.Ordinal) &&
                p.TargetArchitecture == (requiredArch == PeArchitecture.X86 ? PeArchitecture.X86 : PeArchitecture.X64));
        }

        // Сначала ищем точное совпадение по архитектуре .exe (x86 vs x64)
        var exactArchMatch = AllPackages.FirstOrDefault(p =>
            p.TargetArchitecture == requiredArch &&
            p.ProvidedDllNamesLower.Contains(normalized));

        if (exactArchMatch is not null)
        {
            return exactArchMatch;
        }

        // Универсальные пакеты (например, DirectX June 2010 ставит сразу и x86, и x64 библиотеки)
        return AllPackages.FirstOrDefault(p =>
            p.TargetArchitecture == PeArchitecture.Unknown &&
            p.ProvidedDllNamesLower.Contains(normalized));
    }

    /// <summary>
    /// Возвращает true для виртуальных контрактов Windows ApiSet (api-ms-win-core-*, ext-ms-*),
    /// которые разрешаются загрузчиком ядра в памяти (ApiSetSchema.dll) и не лежат как обычные файлы на диске.
    /// </summary>
    public static bool IsVirtualWindowsApiSetContract(string dllName)
    {
        var lower = Path.GetFileName(dllName.Trim()).ToLowerInvariant();
        if (lower.StartsWith("api-ms-win-crt-", StringComparison.Ordinal))
        {
            // Universal CRT реально поставляется с ОС/VC++ и его полезно диагностировать
            return false;
        }

        return lower.StartsWith("api-ms-", StringComparison.Ordinal) ||
               lower.StartsWith("ext-ms-", StringComparison.Ordinal);
    }
}
