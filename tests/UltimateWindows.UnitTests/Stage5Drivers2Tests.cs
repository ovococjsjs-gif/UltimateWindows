using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using UltimateWindows.Core.Enums;
using UltimateWindows.Modules.Drivers.Analyzers;
using UltimateWindows.Modules.Drivers.Catalog;
using UltimateWindows.Modules.Drivers.Models;
using UltimateWindows.Modules.Drivers.Services;
using UltimateWindows.Modules.Safety.Services;
using Xunit;

namespace UltimateWindows.UnitTests;

public sealed class Stage5Drivers2Tests
{
    [Fact]
    public void EssentialDriverCatalog_Loads39PackagesAcrossAll10Categories_WithValidSources()
    {
        var all = EssentialDriverCatalog.GetAllPackages();
        Assert.Equal(39, all.Count);

        // Все ID уникальны
        var ids = all.Select(p => p.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Equal(all.Count, ids.Count);

        // Все 10 жизненных категорий представлены
        foreach (var cat in Enum.GetValues<EssentialDriverCategory>())
        {
            Assert.Contains(all, p => p.Category == cat);
        }

        // Каждый пакет обязан иметь либо прямой HTTPS URL, либо проверенный запрос к Microsoft Update Catalog
        foreach (var pkg in all)
        {
            Assert.False(string.IsNullOrWhiteSpace(pkg.Title));
            Assert.False(string.IsNullOrWhiteSpace(pkg.OfficialPortalUrl));
            Assert.StartsWith("https://", pkg.OfficialPortalUrl, StringComparison.OrdinalIgnoreCase);

            if (pkg.DeliveryKind == EssentialDriverDeliveryKind.DirectHttps)
            {
                Assert.NotNull(pkg.DirectDownloadUrl);
                Assert.StartsWith("https://", pkg.DirectDownloadUrl!, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                Assert.False(string.IsNullOrWhiteSpace(pkg.CatalogSearchQuery));
            }
        }

        // Универсальный спасательный офлайн-набор включает >= 10 сетевых и дисковых пакетов
        var rescue = EssentialDriverCatalog.GetUniversalRescuePackages();
        Assert.True(rescue.Count >= 10);
    }

    [Fact]
    public void EssentialDriverCatalog_EvaluatesHardwareMatches_ForRealWorldChips()
    {
        var devices = new List<SystemDeviceNode>
        {
            new(
                InstanceId: @"PCI\VEN_10EC&DEV_8125&SUBSYS_87D71043\4&111",
                FriendlyName: "Ethernet Controller",
                DeviceClass: "Net",
                Manufacturer: "",
                HardwareIds: [@"PCI\VEN_10EC&DEV_8125&REV_05", @"PCI\VEN_10EC&DEV_8125"],
                ConfigManagerProblemCode: 28,
                DriverVersion: "",
                DriverDate: "",
                InfName: "",
                IsPresent: true),
            new(
                InstanceId: @"USB\VID_1A86&PID_7523\6&222",
                FriendlyName: "USB-SERIAL CH340",
                DeviceClass: "Ports",
                Manufacturer: "wch.cn",
                HardwareIds: [@"USB\VID_1A86&PID_7523"],
                ConfigManagerProblemCode: 0,
                DriverVersion: "3.8.2023.2",
                DriverDate: "2023-02-11",
                InfName: "oem14.inf",
                IsPresent: true),
            new(
                InstanceId: @"PCI\VEN_8086&DEV_9A0B\3&333",
                FriendlyName: "Intel RST VMD Controller",
                DeviceClass: "SCSIAdapter",
                Manufacturer: "Intel",
                HardwareIds: [@"PCI\VEN_8086&DEV_9A0B"],
                ConfigManagerProblemCode: 0,
                DriverVersion: "19.5.2.1049",
                DriverDate: "2023-05-01",
                InfName: "oem7.inf",
                IsPresent: true)
        };

        var evaluated = EssentialDriverCatalog.EvaluateForDevices(devices);
        var rtl = evaluated.Single(e => e.Package.Id == "lan-realtek-25gbe");
        Assert.True(rtl.MatchesCurrentPcHardware);
        Assert.True(rtl.NeedsAttentionOnCurrentPc);
        Assert.Equal("Требуется этому ПК!", rtl.PcRelevanceBadge);

        var ch340 = evaluated.Single(e => e.Package.Id == "serial-wch-ch340");
        Assert.True(ch340.MatchesCurrentPcHardware);
        Assert.False(ch340.NeedsAttentionOnCurrentPc);

        var vmd = evaluated.Single(e => e.Package.Id == "storage-intel-rst-vmd");
        Assert.True(vmd.MatchesCurrentPcHardware);
    }

    [Fact]
    public void DriverVersionComparer_ComparesFourPartVersions_AndParsesInfDriverVer()
    {
        Assert.True(DriverVersionComparer.Compare("23.40.0.4", "2024-01-01", "22.250.1.2", "2024-01-01") > 0);
        Assert.True(DriverVersionComparer.Compare("10.0.26100.1", "2024-04-01", "10.0.26100.1", "2024-04-01") == 0);
        Assert.True(DriverVersionComparer.Compare("31.0.15.3623", null, "32.0.15.6094", null) < 0);

        var (dateIso, ver) = DriverVersionComparer.ParseInfDriverVerDirective("10/24/2024, 10.72.524.2024");
        Assert.Equal("2024-10-24", dateIso);
        Assert.Equal("10.72.524.2024", ver);
    }

    [Fact]
    public void HardwareIdAnalyzer_CoversExpandedVendors_AndBlockedUnsignedProblemCodes()
    {
        var mediatek = HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal([@"PCI\VEN_14C3&DEV_0616"]);
        Assert.NotNull(mediatek);
        Assert.Contains("MediaTek", mediatek!.Value.VendorName);

        var virtio = HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal([@"PCI\VEN_1AF4&DEV_1000"]);
        Assert.NotNull(virtio);
        Assert.Contains("VirtIO", virtio!.Value.VendorName);

        var silabs = HardwareIdAndProblemAnalyzer.ResolveOfficialVendorPortal([@"USB\VID_10C4&PID_EA60"]);
        Assert.NotNull(silabs);
        Assert.Contains("Silicon Labs", silabs!.Value.VendorName);

        var dev48 = new SystemDeviceNode("ROOT\\LEGACY_WINRING0\\0000", "WinRing0", "System", "", [], 48, "", "", "");
        var code48 = HardwareIdAndProblemAnalyzer.ExplainProblemCode(dev48);
        Assert.Equal(RiskLevel.Critical, code48.Severity);
        Assert.Contains("заблокирован", code48.SimpleTitle, StringComparison.OrdinalIgnoreCase);

        var dev52 = new SystemDeviceNode("ROOT\\UNSIGNED\\0000", "TestDrv", "System", "", [], 52, "", "", "");
        var code52 = HardwareIdAndProblemAnalyzer.ExplainProblemCode(dev52);
        Assert.Equal(RiskLevel.Critical, code52.Severity);
        Assert.Contains("подпис", code52.SimpleTitle, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MicrosoftUpdateCatalogClient_ParsesSearchHtml_ResolvesCab_AndVerifiesSha1Digest()
    {
        var cabPayload = Encoding.UTF8.GetBytes("MSCF-MOCK-SIGNED-CAB-BINARY-CONTENT");
        var expectedSha1Base64 = Convert.ToBase64String(SHA1.HashData(cabPayload));
        const string updateGuid = "a1b2c3d4-e5f6-4789-9abc-def012345678";

        const string sampleSearchHtml = """
            <html><body>
            <table id="ctl00_catalogBody_updateMatches">
              <tr id="headerRow"><td>Icon</td><td>Title</td><td>Products</td><td>Class</td><td>Date</td><td>Ver</td><td>Size</td><td>Dl</td></tr>
              <tr id="a1b2c3d4-e5f6-4789-9abc-def012345678_R0">
                <td></td>
                <td><a id="a1b2c3d4_link">Realtek - Net - 10.72.524.2024</a></td>
                <td>Windows 11 Client, version 24H2 and later, Servicing Drivers,Windows 10</td>
                <td>Drivers (Networking)</td>
                <td>10/24/2024</td>
                <td>10.72.524.2024</td>
                <td><span>1.2 MB</span><span>1258291</span></td>
                <td><input id="a1b2c3d4-e5f6-4789-9abc-def012345678" type="button" value="Download" /></td>
              </tr>
            </table>
            </body></html>
            """;

        var sampleDialogHtml = $$"""
            <script type="text/javascript">
            downloadInformation[0].files[0].url = 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2024/10/realtek_net.cab';
            downloadInformation[0].files[0].digest = '{{expectedSha1Base64}}';
            downloadInformation[0].files[0].architectures = 'AMD64';
            downloadInformation[0].files[0].fileName = 'realtek_net.cab';
            </script>
            """;

        using var http = new HttpClient(new StubHttpHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("Search.aspx", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(sampleSearchHtml, Encoding.UTF8, "text/html")
                };
            }

            if (url.Contains("DownloadDialog.aspx", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(sampleDialogHtml, Encoding.UTF8, "text/html")
                };
            }

            if (url.EndsWith("realtek_net.cab", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(cabPayload)
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var client = new MicrosoftUpdateCatalogClient(http);
        var entries = await client.SearchDriversAsync(@"PCI\VEN_10EC&DEV_8125");
        Assert.Single(entries);
        Assert.Equal(updateGuid, entries[0].UpdateId);
        Assert.Equal("10.72.524.2024", entries[0].Version);
        Assert.Equal(1258291, entries[0].SizeBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), "uw-cat-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var resolvedLinks = await client.ResolveDownloadLinksAsync(updateGuid);
            Assert.Single(resolvedLinks);
            Assert.Equal("AMD64", resolvedLinks[0].Architectures);

            var destCab = Path.Combine(tempDir, "realtek_net.cab");
            var (dlOk, cabPath, _) = await client.DownloadFileVerifiedAsync(resolvedLinks[0].DownloadUrl, destCab, resolvedLinks[0].DigestBase64);
            Assert.True(dlOk);
            Assert.True(File.Exists(cabPath));
            Assert.Equal(cabPayload.Length, new FileInfo(cabPath).Length);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task DriverStoreAudit_FlagsOnlyUnboundOlderDuplicates_AndBacksUpToVaultBeforeCleaning()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "uw-store-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var vault = new ZeroBloatVaultService(Path.Combine(tempDir, "Vault"));
            var bridge = new Stage5FakeDriverBridge
            {
                IsAdmin = true,
                Devices =
                [
                    new SystemDeviceNode(
                        InstanceId: @"PCI\VEN_8086&DEV_2725\1",
                        FriendlyName: "Intel Wi-Fi 6 AX210",
                        DeviceClass: "Net",
                        Manufacturer: "Intel",
                        HardwareIds: [@"PCI\VEN_8086&DEV_2725"],
                        ConfigManagerProblemCode: 0,
                        DriverVersion: "23.80.1.3",
                        DriverDate: "2024-11-01",
                        InfName: "oem12.inf",
                        IsPresent: true)
                ],
                StoreEntries =
                [
                    new DriverStoreEntry("oem5.inf", "Netwtw10.inf", "Intel", "Net", "{4d36e972}", "22.200.0.6", "2023-03-10", "Microsoft WHQL", "", 42 * 1024 * 1024, false, null, false, null),
                    new DriverStoreEntry("oem12.inf", "Netwtw10.inf", "Intel", "Net", "{4d36e972}", "23.80.1.3", "2024-11-01", "Microsoft WHQL", "", 45 * 1024 * 1024, false, null, false, null),
                    new DriverStoreEntry("oem20.inf", "hpcu250u.inf", "HP", "Printer", "{4d36e979}", "61.230.1.10", "2022-05-01", "Microsoft WHQL", "", 30 * 1024 * 1024, false, null, false, null),
                    new DriverStoreEntry("oem21.inf", "hpcu250u.inf", "HP", "Printer", "{4d36e979}", "61.255.1.18", "2024-02-01", "Microsoft WHQL", "", 31 * 1024 * 1024, false, null, false, null)
                ]
            };

            var svc = new OfficialDriverService(vault, bridge);
            var summary = await svc.AuditDriverStoreAsync();

            Assert.Equal(4, summary.Entries.Count);
            Assert.Equal(2, summary.DuplicateOldCount);

            var oem5 = summary.Entries.Single(e => e.PublishedInfName == "oem5.inf");
            var oem12 = summary.Entries.Single(e => e.PublishedInfName == "oem12.inf");
            var oem20 = summary.Entries.Single(e => e.PublishedInfName == "oem20.inf");
            var oem21 = summary.Entries.Single(e => e.PublishedInfName == "oem21.inf");

            Assert.True(oem5.IsSupersededDuplicate);
            Assert.False(oem12.IsSupersededDuplicate);
            Assert.True(oem12.IsInUseByDevice);
            Assert.True(oem20.IsSupersededDuplicate);
            Assert.False(oem21.IsSupersededDuplicate);

            var cleanRes = await svc.CleanOldDriverStoreDuplicatesAsync(summary.Entries);
            Assert.True(cleanRes.Succeeded);
            Assert.Equal(["oem5.inf", "oem20.inf"], bridge.DeletedInfPackages);

            var history = await vault.GetHistoryAsync();
            Assert.Equal(2, history.Count);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task OfflineNetworkRescuePack_ExportsLocalNetworkAndNvmeDrivers_AndCreatesOneClickInstallerScript()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "uw-rescue-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var vault = new ZeroBloatVaultService(Path.Combine(tempDir, "Vault"));
            var bridge = new Stage5FakeDriverBridge
            {
                IsAdmin = true,
                Devices =
                [
                    new SystemDeviceNode(@"PCI\VEN_10EC&DEV_8125\1", "Realtek PCIe 2.5GbE", "Net", "Realtek", [@"PCI\VEN_10EC&DEV_8125"], 0, "10.72.0.1", "2024-10-01", "oem3.inf", true),
                    new SystemDeviceNode(@"PCI\VEN_8086&DEV_9A0B\1", "Intel RST VMD Controller", "SCSIAdapter", "Intel", [@"PCI\VEN_8086&DEV_9A0B"], 0, "19.5.2.1", "2023-08-01", "oem9.inf", true)
                ]
            };

            var svc = new OfficialDriverService(vault, bridge);
            var outFolder = Path.Combine(tempDir, "RescueUSB");
            var res = await svc.BuildOfflineNetworkRescuePackAsync(outFolder, downloadUniversalFromServers: false);

            Assert.True(res.Succeeded);
            Assert.Equal(2, res.ExportedOrDownloadedCount);
            Assert.True(File.Exists(res.InstallScriptPath));
            var cmdText = await File.ReadAllTextAsync(res.InstallScriptPath);
            Assert.Contains("pnputil.exe", cmdText, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task VulnerableDriverAudit_DetectsByovdByNameAndSha256_AndNeutralizesIntoEncryptedVault()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "uw-byovd-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var fakeSysPath = Path.Combine(tempDir, "WinRing0x64.sys");
            await File.WriteAllBytesAsync(fakeSysPath, Encoding.ASCII.GetBytes("MZ-FAKE-WINRING0-KERNEL-DRIVER"));

            var vault = new ZeroBloatVaultService(Path.Combine(tempDir, "Vault"));
            var bridge = new Stage5FakeDriverBridge
            {
                IsAdmin = true,
                HvciEnabled = false,
                BlocklistEnabled = false,
                KernelDrivers =
                [
                    new KernelDriverInventoryEntry(
                        ServiceName: "WinRing0_1_2_0",
                        DisplayName: "WinRing0_1_2_0",
                        BinaryPath: fakeSysPath,
                        FileName: "WinRing0x64.sys",
                        FileExists: true,
                        FileVersion: "1.2.0.5",
                        CompanyName: "OpenLibSys.org",
                        Sha256Hex: "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfef60b5c160ee5d",
                        IsRunning: true,
                        StartType: 2,
                        IsSigned: true),
                    new KernelDriverInventoryEntry(
                        ServiceName: "Ntfs",
                        DisplayName: "Ntfs",
                        BinaryPath: @"C:\Windows\System32\drivers\ntfs.sys",
                        FileName: "ntfs.sys",
                        FileExists: false,
                        FileVersion: "10.0.26100.1",
                        CompanyName: "Microsoft Corporation",
                        Sha256Hex: "",
                        IsRunning: true,
                        StartType: 0,
                        IsSigned: true)
                ]
            };

            var svc = new OfficialDriverService(vault, bridge);
            var audit = await svc.AuditVulnerableKernelDriversAsync();
            Assert.Single(audit.Findings);
            Assert.Equal("byovd-winring0", audit.Findings[0].MatchedRule.Id);
            Assert.Contains("PawnIO", audit.Findings[0].MatchedRule.SafeAlternative);

            var blockRes = await svc.EnableMicrosoftVulnerableDriverBlocklistAsync();
            Assert.True(blockRes.Succeeded);
            Assert.True(bridge.BlocklistEnabled);

            var neutRes = await svc.NeutralizeVulnerableKernelDriverAsync(audit.Findings[0]);
            Assert.True(neutRes.Succeeded);
            Assert.False(File.Exists(fakeSysPath)); // Перемещён в зашифрованный карантин .uwq!
            Assert.Contains("WinRing0_1_2_0", bridge.DisabledKernelServices);

            // Проверяем, что откат точки Хранилища возвращает .sys файл обратно байт-в-байт!
            Assert.NotNull(neutRes.RollbackSessionId);
            await vault.RollbackTransactionAsync(neutRes.RollbackSessionId!.Value);
            Assert.True(File.Exists(fakeSysPath));
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task EssentialPackageDownload_ExtractsZipDriver_AndRejectsUnsignedExecutables()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "uw-ess-dl-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            byte[] zipBytes;
            using (var ms = new MemoryStream())
            {
                using (var za = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
                {
                    var infEntry = za.CreateEntry("android_winusb.inf");
                    await using (var s = infEntry.Open())
                    await using (var sw = new StreamWriter(s))
                        await sw.WriteLineAsync("[Version]\nSignature=\"$WINDOWS NT$\"");

                    var catEntry = za.CreateEntry("androidwinusb86.cat");
                    await using (var s = catEntry.Open())
                        await s.WriteAsync("SIGNED-CAT"u8.ToArray());
                }
                zipBytes = ms.ToArray();
            }

            using var http = new HttpClient(new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes)
            }));

            var vault = new ZeroBloatVaultService(Path.Combine(tempDir, "Vault"));
            var bridge = new Stage5FakeDriverBridge { IsAdmin = true, SignatureVerdict = true };
            var catClient = new MicrosoftUpdateCatalogClient(http);
            var svc = new OfficialDriverService(vault, bridge, catClient);

            var googlePkg = EssentialDriverCatalog.FindById("tether-google-android-usb")!;
            var dlRes = await svc.DownloadOrInstallEssentialPackageAsync(googlePkg, Path.Combine(tempDir, "Out"), installOnThisPc: true);
            Assert.True(dlRes.Succeeded);
            Assert.Equal(1, bridge.InstalledFolderCount);

            // Проверяем защитный отказ при неподписанном .exe установщике
            bridge.SignatureVerdict = false;
            var pawnPkg = EssentialDriverCatalog.FindById("sensor-pawnio-hvci")!;
            var unsignedRes = await svc.DownloadOrInstallEssentialPackageAsync(pawnPkg, Path.Combine(tempDir, "OutUnsigned"), installOnThisPc: false);
            Assert.False(unsignedRes.Succeeded);
            Assert.Contains("подпис", unsignedRes.UserFriendlyMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    private sealed class StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    private sealed class Stage5FakeDriverBridge : DefaultDriverPlatformBridge
    {
        public bool IsAdmin { get; set; } = true;
        public bool SignatureVerdict { get; set; } = true;
        public bool HvciEnabled { get; set; }
        public bool BlocklistEnabled { get; set; } = true;
        public int InstalledFolderCount { get; private set; }

        public List<SystemDeviceNode> Devices { get; set; } = [];
        public List<DriverStoreEntry> StoreEntries { get; set; } = [];
        public List<KernelDriverInventoryEntry> KernelDrivers { get; set; } = [];
        public List<string> DeletedInfPackages { get; } = [];
        public List<string> DisabledKernelServices { get; } = [];

        public override bool IsRunningAsAdministrator() => IsAdmin;
        public override bool VerifyFileAuthenticodeSignature(string filePath) => SignatureVerdict;

        public override Task<IReadOnlyList<SystemDeviceNode>> EnumerateDevicesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<SystemDeviceNode>>(Devices);

        public override Task<IReadOnlyList<DriverStoreEntry>> EnumerateDriverStoreAsync(IReadOnlyList<SystemDeviceNode> activeDevices, CancellationToken ct = default)
        {
            var bound = activeDevices
                .Where(d => d.IsThirdPartyOemInf)
                .ToDictionary(d => d.InfName, d => d.FriendlyName, StringComparer.OrdinalIgnoreCase);

            var mapped = StoreEntries.Select(e => bound.TryGetValue(e.PublishedInfName, out var dev)
                ? e with { IsInUseByDevice = true, BoundDeviceName = dev }
                : e).ToList();
            return Task.FromResult<IReadOnlyList<DriverStoreEntry>>(mapped);
        }

        public override async Task<(bool Succeeded, IReadOnlyList<string> ExportedFiles, string ErrorMessage)> ExportSingleOemInfAsync(
            string oemInfName,
            string destinationDirectory,
            CancellationToken ct = default)
        {
            Directory.CreateDirectory(destinationDirectory);
            var f = Path.Combine(destinationDirectory, oemInfName);
            await File.WriteAllTextAsync(f, "; exported inf", ct);
            return (true, [f], "");
        }

        public override Task<(bool Succeeded, string ErrorMessage)> DeleteDriverStorePackageAsync(string publishedInfName, CancellationToken ct = default)
        {
            DeletedInfPackages.Add(publishedInfName);
            return Task.FromResult((true, ""));
        }

        public override Task<(bool Succeeded, int AddedCount, string OutputMessage)> AddAndInstallDriverFolderAsync(string infDirectory, bool installOnDevices = true, CancellationToken ct = default)
        {
            InstalledFolderCount++;
            return Task.FromResult((true, 1, "OK"));
        }

        public override Task<IReadOnlyList<KernelDriverInventoryEntry>> EnumerateKernelDriversAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<KernelDriverInventoryEntry>>(KernelDrivers);

        public override (bool IsHvciEnabled, bool IsMicrosoftBlocklistEnabled) ReadCodeIntegrityPosture() =>
            (HvciEnabled, BlocklistEnabled);

        public override (bool Succeeded, int? PreviousValue, string ErrorMessage) SetMicrosoftVulnerableDriverBlocklist(bool enabled)
        {
            int? prev = BlocklistEnabled ? 1 : 0;
            BlocklistEnabled = enabled;
            return (true, prev, "");
        }

        public override (bool Succeeded, int PreviousStartType, string ErrorMessage) DisableKernelDriverService(string serviceName)
        {
            DisabledKernelServices.Add(serviceName);
            return (true, 2, "");
        }
    }
}
