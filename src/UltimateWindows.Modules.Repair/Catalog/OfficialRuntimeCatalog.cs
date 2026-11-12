using UltimateWindows.Modules.Repair.Models;

namespace UltimateWindows.Modules.Repair.Catalog;

/// <summary>
/// Полный каталог официальных подписанных сред выполнения Microsoft / Khronos / OpenAL (Этап 3 — 22 пакета):
/// Visual C++ 2005–2026 (x86/x64/ARM64), DirectX June 2010, .NET Framework 3.5 и 4.8.1,
/// .NET Desktop Runtime 6 / 8 / 9 / 10, Microsoft Edge WebView2 Evergreen, XNA 4.0, OpenAL и Vulkan Runtime.
/// Полностью исключает опасное скачивание одиночных «левых» .dll файлов со сторонних сайтов.
/// </summary>
public static class OfficialRuntimeCatalog
{
    private static readonly IReadOnlyList<OfficialRuntimePackage> AllPackages =
    [
        // ==================== MICROSOFT VISUAL C++ v14 (2015–2026) ====================
        new(
            PackageKey: "vcredist-2015-2022-x64",
            WingetPackageId: "Microsoft.VCRedist.2015+.x64",
            FriendlyName: "Microsoft Visual C++ 2015–2026 Redistributable v14 (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower:
            [
                "vcruntime140.dll", "vcruntime140_1.dll", "vcruntime140_threads.dll",
                "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
                "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
                "concrt140.dll", "vcomp140.dll", "vcamp140.dll", "mfc140.dll", "mfc140u.dll",
                "mfcm140u.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll",
                "api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll"
            ],
            DirectDownloadUrl: "https://aka.ms/vc14/vc_redist.x64.exe",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "vcredist-2015-2022-x86",
            WingetPackageId: "Microsoft.VCRedist.2015+.x86",
            FriendlyName: "Microsoft Visual C++ 2015–2026 Redistributable v14 (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower:
            [
                "vcruntime140.dll", "vcruntime140_threads.dll",
                "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
                "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
                "concrt140.dll", "vcomp140.dll", "vcamp140.dll", "mfc140.dll", "mfc140u.dll",
                "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll",
                "api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll"
            ],
            DirectDownloadUrl: "https://aka.ms/vc14/vc_redist.x86.exe",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "vcredist-2015-2022-arm64",
            WingetPackageId: "Microsoft.VCRedist.2015+.arm64",
            FriendlyName: "Microsoft Visual C++ 2015–2026 Redistributable v14 (ARM64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.Arm64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower:
            [
                "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "concrt140.dll", "vcomp140.dll", "mfc140u.dll"
            ],
            DirectDownloadUrl: "https://aka.ms/vc14/vc_redist.arm64.exe",
            Category: "Visual C++"),

        // ==================== MICROSOFT VISUAL C++ 2013 (v12) ====================
        new(
            PackageKey: "vcredist-2013-x64",
            WingetPackageId: "Microsoft.VCRedist.2013.x64",
            FriendlyName: "Microsoft Visual C++ 2013 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr120.dll", "msvcp120.dll", "vcomp120.dll", "vcamp120.dll", "mfc120.dll", "mfc120u.dll"],
            DirectDownloadUrl: "https://aka.ms/highdpimfc2013x64enu",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "vcredist-2013-x86",
            WingetPackageId: "Microsoft.VCRedist.2013.x86",
            FriendlyName: "Microsoft Visual C++ 2013 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr120.dll", "msvcp120.dll", "vcomp120.dll", "vcamp120.dll", "mfc120.dll", "mfc120u.dll"],
            DirectDownloadUrl: "https://aka.ms/highdpimfc2013x86enu",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        // ==================== MICROSOFT VISUAL C++ 2012 Update 4 (v11) ====================
        new(
            PackageKey: "vcredist-2012-x64",
            WingetPackageId: "Microsoft.VCRedist.2012.x64",
            FriendlyName: "Microsoft Visual C++ 2012 Update 4 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr110.dll", "msvcp110.dll", "vcomp110.dll", "vcamp110.dll", "mfc110.dll", "mfc110u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "vcredist-2012-x86",
            WingetPackageId: "Microsoft.VCRedist.2012.x86",
            FriendlyName: "Microsoft Visual C++ 2012 Update 4 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
            ProvidedDllNamesLower: ["msvcr110.dll", "msvcp110.dll", "vcomp110.dll", "vcamp110.dll", "mfc110.dll", "mfc110u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        // ==================== MICROSOFT VISUAL C++ 2010 SP1 (v10) ====================
        new(
            PackageKey: "vcredist-2010-x64",
            WingetPackageId: "Microsoft.VCRedist.2010.x64",
            FriendlyName: "Microsoft Visual C++ 2010 SP1 Redistributable (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/q /norestart",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=26999",
            ProvidedDllNamesLower: ["msvcr100.dll", "msvcp100.dll", "vcomp100.dll", "mfc100.dll", "mfc100u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "vcredist-2010-x86",
            WingetPackageId: "Microsoft.VCRedist.2010.x86",
            FriendlyName: "Microsoft Visual C++ 2010 SP1 Redistributable (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/q /norestart",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=26999",
            ProvidedDllNamesLower: ["msvcr100.dll", "msvcp100.dll", "vcomp100.dll", "mfc100.dll", "mfc100u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe",
            Category: "Visual C++",
            IsRecommendedBaseline: true),

        // ==================== MICROSOFT VISUAL C++ 2008 SP1 (v9) ====================
        new(
            PackageKey: "vcredist-2008-x64",
            WingetPackageId: "Microsoft.VCRedist.2008.x64",
            FriendlyName: "Microsoft Visual C++ 2008 SP1 MFC Security Update (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/q",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=26368",
            ProvidedDllNamesLower: ["msvcr90.dll", "msvcp90.dll", "vcomp90.dll", "mfc90.dll", "mfc90u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe",
            Category: "Visual C++"),

        new(
            PackageKey: "vcredist-2008-x86",
            WingetPackageId: "Microsoft.VCRedist.2008.x86",
            FriendlyName: "Microsoft Visual C++ 2008 SP1 MFC Security Update (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/q",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=26368",
            ProvidedDllNamesLower: ["msvcr90.dll", "msvcp90.dll", "vcomp90.dll", "mfc90.dll", "mfc90u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe",
            Category: "Visual C++"),

        // ==================== MICROSOFT VISUAL C++ 2005 SP1 (v8) ====================
        new(
            PackageKey: "vcredist-2005-x64",
            WingetPackageId: "Microsoft.VCRedist.2005.x64",
            FriendlyName: "Microsoft Visual C++ 2005 SP1 MFC Security Update (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/q",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=26347",
            ProvidedDllNamesLower: ["msvcr80.dll", "msvcp80.dll", "mfc80.dll", "mfc80u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE",
            Category: "Visual C++"),

        new(
            PackageKey: "vcredist-2005-x86",
            WingetPackageId: "Microsoft.VCRedist.2005.x86",
            FriendlyName: "Microsoft Visual C++ 2005 SP1 MFC Security Update (x86)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/q",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=26347",
            ProvidedDllNamesLower: ["msvcr80.dll", "msvcp80.dll", "mfc80.dll", "mfc80u.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE",
            Category: "Visual C++"),

        // ==================== DIRECTX, XNA, OPENAL, VULKAN ====================
        new(
            PackageKey: "directx-june-2010",
            WingetPackageId: "Microsoft.DirectX",
            FriendlyName: "Microsoft DirectX End-User Runtimes (June 2010)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "/Q",
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
            ],
            DirectDownloadUrl: "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe",
            Category: "DirectX и игры",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "xna-framework-40",
            WingetPackageId: "Microsoft.XNARedist",
            FriendlyName: "Microsoft XNA Framework Redistributable 4.0",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X86,
            SilentInstallArgs: "/qn /norestart",
            OfficialDownloadPageUrl: "https://www.microsoft.com/download/details.aspx?id=20914",
            ProvidedDllNamesLower: ["microsoft.xna.framework.dll"],
            DirectDownloadUrl: "https://download.microsoft.com/download/A/C/2/AC2C903B-E6E8-42C2-9FD7-BEBAC362A930/xnafx40_redist.msi",
            Category: "DirectX и игры"),

        new(
            PackageKey: "openal-runtime",
            WingetPackageId: "OpenAL.OpenAL",
            FriendlyName: "OpenAL Cross-Platform 3D Audio Runtime",
            PublisherName: "OpenAL / Creative Labs",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "/s",
            OfficialDownloadPageUrl: "https://www.openal.org/downloads/",
            ProvidedDllNamesLower: ["openal32.dll", "wrap_oal.dll"],
            Category: "DirectX и игры"),

        new(
            PackageKey: "vulkan-runtime-x64",
            WingetPackageId: "KhronosGroup.VulkanRT",
            FriendlyName: "Khronos Vulkan Runtime (загрузчик vulkan-1.dll)",
            PublisherName: "LunarG / Khronos Group",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/S",
            OfficialDownloadPageUrl: "https://vulkan.lunarg.com/sdk/home",
            ProvidedDllNamesLower: ["vulkan-1.dll"],
            Category: "DirectX и игры"),

        // ==================== .NET FRAMEWORK И .NET DESKTOP RUNTIME ====================
        new(
            PackageKey: "dotnet-fx-35",
            WingetPackageId: "Microsoft.DotNet.Framework.DeveloperPack_4",
            FriendlyName: "Microsoft .NET Framework 3.5 (включая 2.0 и 3.0)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "",
            OfficialDownloadPageUrl: "https://learn.microsoft.com/dotnet/framework/install/dotnet-35-windows",
            ProvidedDllNamesLower: ["mscorwks.dll"],
            OptionalWindowsFeatureName: "NetFx3",
            Category: ".NET"),

        new(
            PackageKey: "dotnet-fx-481",
            WingetPackageId: "Microsoft.DotNet.Framework.DeveloperPack_4",
            FriendlyName: "Microsoft .NET Framework 4.8.1 Runtime",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "/q /norestart",
            OfficialDownloadPageUrl: "https://dotnet.microsoft.com/download/dotnet-framework/net481",
            ProvidedDllNamesLower: ["clr.dll", "mscoree.dll"],
            DirectDownloadUrl: "https://go.microsoft.com/fwlink/?LinkId=2203305",
            Category: ".NET"),

        new(
            PackageKey: "dotnet-desktop-6-x64",
            WingetPackageId: "Microsoft.DotNet.DesktopRuntime.6",
            FriendlyName: "Microsoft .NET 6 Desktop Runtime (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://dotnet.microsoft.com/download/dotnet/6.0",
            ProvidedDllNamesLower: [],
            DirectDownloadUrl: "https://aka.ms/dotnet/6.0/windowsdesktop-runtime-win-x64.exe",
            Category: ".NET"),

        new(
            PackageKey: "dotnet-desktop-8-x64",
            WingetPackageId: "Microsoft.DotNet.DesktopRuntime.8",
            FriendlyName: "Microsoft .NET 8 LTS Desktop Runtime (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://dotnet.microsoft.com/download/dotnet/8.0",
            ProvidedDllNamesLower: ["hostfxr.dll", "coreclr.dll", "hostpolicy.dll"],
            DirectDownloadUrl: "https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe",
            Category: ".NET",
            IsRecommendedBaseline: true),

        new(
            PackageKey: "dotnet-desktop-10-x64",
            WingetPackageId: "Microsoft.DotNet.DesktopRuntime.10",
            FriendlyName: "Microsoft .NET 10 LTS Desktop Runtime (x64)",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.X64,
            SilentInstallArgs: "/install /quiet /norestart",
            OfficialDownloadPageUrl: "https://dotnet.microsoft.com/download/dotnet/10.0",
            ProvidedDllNamesLower: [],
            DirectDownloadUrl: "https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-x64.exe",
            Category: ".NET",
            IsRecommendedBaseline: true),

        // ==================== MICROSOFT EDGE WEBVIEW2 ====================
        new(
            PackageKey: "edge-webview2-evergreen",
            WingetPackageId: "Microsoft.EdgeWebView2Runtime",
            FriendlyName: "Microsoft Edge WebView2 Evergreen Runtime",
            PublisherName: "Microsoft Corporation",
            TargetArchitecture: PeArchitecture.Unknown,
            SilentInstallArgs: "/silent /install",
            OfficialDownloadPageUrl: "https://developer.microsoft.com/microsoft-edge/webview2/",
            ProvidedDllNamesLower: ["webview2loader.dll", "embeddedbrowserwebview.dll"],
            DirectDownloadUrl: "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
            Category: "WebView2",
            IsRecommendedBaseline: true)
    ];

    public static IReadOnlyList<OfficialRuntimePackage> GetAllPackages() => AllPackages;

    public static OfficialRuntimePackage? GetByKey(string packageKey) =>
        AllPackages.FirstOrDefault(p => string.Equals(p.PackageKey, packageKey, StringComparison.OrdinalIgnoreCase));

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

        // Специальное правило для всех api-ms-win-crt-*.dll -> пакет VC++ 2015-2026 нужной разрядности
        if (normalized.StartsWith("api-ms-win-crt-", StringComparison.Ordinal))
        {
            var target = requiredArch is PeArchitecture.X86 or PeArchitecture.Arm64 ? requiredArch : PeArchitecture.X64;
            return AllPackages.FirstOrDefault(p =>
                p.PackageKey.StartsWith("vcredist-2015-2022", StringComparison.Ordinal) &&
                p.TargetArchitecture == target);
        }

        // Сначала ищем точное совпадение по архитектуре .exe (x86 vs x64 vs ARM64)
        var exactArchMatch = AllPackages.FirstOrDefault(p =>
            p.TargetArchitecture == requiredArch &&
            p.ProvidedDllNamesLower.Contains(normalized));

        if (exactArchMatch is not null)
        {
            return exactArchMatch;
        }

        // Универсальные пакеты (например, DirectX June 2010 или WebView2)
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
            return false;
        }

        return lower.StartsWith("api-ms-", StringComparison.Ordinal) ||
               lower.StartsWith("ext-ms-", StringComparison.Ordinal);
    }

    /// <summary>
    /// Проверяет, принадлежит ли URL прямой загрузки доверенному официальному домену издателя.
    /// </summary>
    public static bool IsTrustedOfficialDownloadUrl(Uri? uri)
    {
        if (uri is null || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        return host == "aka.ms" ||
               host == "go.microsoft.com" ||
               host.EndsWith(".microsoft.com", StringComparison.Ordinal) ||
               host.EndsWith(".visualstudio.microsoft.com", StringComparison.Ordinal) ||
               host.EndsWith(".msecnd.net", StringComparison.Ordinal) ||
               host.EndsWith(".azureedge.net", StringComparison.Ordinal);
    }
}
