using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using UltimateWindows.Modules.Hardware.Contracts;
using UltimateWindows.Modules.Hardware.Models;
using UltimateWindows.Modules.Hardware.Parsers;
using UltimateWindows.Modules.Hardware.Probes;

namespace UltimateWindows.NativeInterop.Hardware;

/// <summary>
/// Реальный Windows-провайдер аппаратной инвентаризации, датчиков без WinRing0 (SMBIOS, CPUID, NVML, S.M.A.R.T. IOCTL, EDID)
/// и безопасного переключения системных режимов (частота экрана, схемы питания).
/// </summary>
public sealed class WindowsHardwarePlatformProvider : IHardwarePlatformProvider
{
    private static readonly Guid PowerSaverGuid = new("a1841308-3541-4fab-bc81-f71556f20b4a");
    private static readonly Guid BalancedGuid = new("381b4222-f694-41f0-9685-ff5bb260df2e");
    private static readonly Guid HighPerformanceGuid = new("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
    private static readonly Guid UltimatePerformanceGuid = new("e9a42b02-d5df-448d-aa00-03f14749eb61");

    public Task<HardwareSnapshot> CaptureSnapshotAsync(CancellationToken ct = default)
    {
        return Task.Run(() => CaptureSnapshotCore(), ct);
    }

    public Task<(double? CpuTempC, double? GpuTempC)> PollThermalSensorsAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            double? gpuTemp = null;
            var nvmlList = TryQueryNvidiaNvmlTelemetry();
            if (nvmlList.Count > 0)
            {
                gpuTemp = nvmlList.Max(x => x.TempC);
            }

            return ((double?)null, gpuTemp);
        }, ct);
    }

    public Task<(bool Success, int PreviousHz, string Message)> TrySetDisplayRefreshRateAsync(
        string gdiDeviceName,
        int targetRefreshHz,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((false, 60, "Доступно только на Windows."));
        }

        var devMode = CreateDevMode();
        if (!EnumDisplaySettingsExW(gdiDeviceName, ENUM_CURRENT_SETTINGS, ref devMode, 0))
        {
            return Task.FromResult((false, 60, $"Не удалось прочитать текущий видеорежим монитора {gdiDeviceName}."));
        }

        var prevHz = devMode.dmDisplayFrequency;
        devMode.dmDisplayFrequency = targetRefreshHz;
        devMode.dmFields = DM_DISPLAYFREQUENCY;

        var testResult = ChangeDisplaySettingsExW(gdiDeviceName, ref devMode, IntPtr.Zero, CDS_TEST, IntPtr.Zero);
        if (testResult != DISP_CHANGE_SUCCESSFUL)
        {
            return Task.FromResult((false, prevHz, $"Видеодрайвер отклонил тестовый режим {targetRefreshHz} Гц (код {testResult})."));
        }

        var applyResult = ChangeDisplaySettingsExW(gdiDeviceName, ref devMode, IntPtr.Zero, CDS_UPDATEREGISTRY, IntPtr.Zero);
        return applyResult == DISP_CHANGE_SUCCESSFUL
            ? Task.FromResult((true, prevHz, $"Частота {targetRefreshHz} Гц успешно применена."))
            : Task.FromResult((false, prevHz, $"Ошибка применения частоты {targetRefreshHz} Гц (код {applyResult})."));
    }

    public Task<(bool Success, Guid PreviousSchemeGuid, string Message)> TrySetActivePowerSchemeAsync(
        Guid targetSchemeGuid,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult((false, Guid.Empty, "Доступно только на Windows."));
        }

        var prevGuid = GetActivePowerSchemeGuidOrDefault();

        // Если High Performance скрыта на Modern Standby ноутбуке, откатываемся на стандартную Balanced
        var res = PowerSetActiveScheme(IntPtr.Zero, ref targetSchemeGuid);
        if (res != 0 && targetSchemeGuid == HighPerformanceGuid)
        {
            var balanced = BalancedGuid;
            res = PowerSetActiveScheme(IntPtr.Zero, ref balanced);
        }

        return res == 0
            ? Task.FromResult((true, prevGuid, "Схема электропитания успешно переключена."))
            : Task.FromResult((false, prevGuid, $"Не удалось переключить схему электропитания (Win32 код {res})."));
    }

    private static HardwareSnapshot CaptureSnapshotCore()
    {
        var smbios = ReadAndParseSmbios();
        var cpu = QueryCpuHardwareInfo();
        var memory = BuildMemorySubsystem(smbios.MemorySlots);
        var gpus = QueryGpuInventory();
        var drives = QueryStorageDrives();
        var monitors = QueryDisplaysAndEdid();
        var battery = QueryBatteryStatus();
        var powerPlan = QueryActivePowerPlan();

        return new HardwareSnapshot(
            CapturedAtUtc: DateTimeOffset.UtcNow,
            Cpu: cpu,
            Motherboard: smbios.Motherboard,
            Memory: memory,
            Gpus: gpus,
            Drives: drives,
            Monitors: monitors,
            Battery: battery,
            ActivePowerPlan: powerPlan);
    }

    // ==================== 1. SMBIOS ('RSMB') ====================
    private static SmbiosParsedData ReadAndParseSmbios()
    {
        if (!OperatingSystem.IsWindows())
        {
            return SmbiosBinaryParser.ParseWindowsRawSmbios(ReadOnlySpan<byte>.Empty);
        }

        const uint rsmbSignature = 0x52534D42; // 'RSMB' в Big-Endian сигнатуре провайдера
        var size = GetSystemFirmwareTable(rsmbSignature, 0, IntPtr.Zero, 0);
        if (size == 0 || size > 1024 * 1024)
        {
            return SmbiosBinaryParser.ParseWindowsRawSmbios(ReadOnlySpan<byte>.Empty);
        }

        var buffer = new byte[size];
        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                var written = GetSystemFirmwareTable(rsmbSignature, 0, (IntPtr)ptr, size);
                if (written == 0)
                {
                    return SmbiosBinaryParser.ParseWindowsRawSmbios(ReadOnlySpan<byte>.Empty);
                }
            }
        }

        return SmbiosBinaryParser.ParseWindowsRawSmbios(buffer);
    }

    // ==================== 2. CPU TOPOLOGY & CACHE ====================
    private static CpuHardwareInfo QueryCpuHardwareInfo()
    {
        var cpuid = CpuIdProbe.QueryCurrentProcessor();
        var logicalCount = Environment.ProcessorCount;
        var physicalCores = Math.Max(1, logicalCount / 2);
        var pCores = 0;
        var eCores = 0;
        long l1Bytes = 0, l2Bytes = 0, l3Bytes = 0;
        var baseMhz = 0;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var cpuKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
                if (cpuKey?.GetValue("~MHz") is int regMhz)
                {
                    baseMhz = regMhz;
                }
            }
            catch
            {
                // Не фатально
            }

            QueryProcessorRelations(ref physicalCores, ref pCores, ref eCores, ref l1Bytes, ref l2Bytes, ref l3Bytes);
        }

        if (pCores + eCores == 0)
        {
            pCores = physicalCores;
        }

        return new CpuHardwareInfo(
            Vendor: cpuid.Vendor,
            BrandName: cpuid.BrandString,
            Family: cpuid.Family,
            Model: cpuid.Model,
            Stepping: cpuid.Stepping,
            PhysicalCores: physicalCores,
            LogicalProcessors: logicalCount,
            PerformanceCores: pCores,
            EfficientCores: eCores,
            L1CacheBytes: l1Bytes,
            L2CacheBytes: l2Bytes,
            L3CacheBytes: l3Bytes,
            BaseClockMhz: baseMhz,
            CurrentClockMhz: baseMhz,
            PackageTemperatureC: null,
            TotalLoadPercent: null,
            InstructionSets: cpuid.InstructionSets);
    }

    private static void QueryProcessorRelations(
        ref int physicalCores,
        ref int pCores,
        ref int eCores,
        ref long l1Bytes,
        ref long l2Bytes,
        ref long l3Bytes)
    {
        uint len = 0;
        _ = GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, IntPtr.Zero, ref len);
        if (len == 0 || len > 4 * 1024 * 1024)
        {
            return;
        }

        var raw = new byte[len];
        unsafe
        {
            fixed (byte* pBuf = raw)
            {
                if (!GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, (IntPtr)pBuf, ref len))
                {
                    return;
                }
            }
        }

        var coreCount = 0;
        var highEffCount = 0;
        var baseEffCount = 0;

        var offset = 0;
        while (offset + 8 <= len)
        {
            var relation = (LOGICAL_PROCESSOR_RELATIONSHIP)BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(offset, 4));
            var entrySize = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 4, 4));
            if (entrySize <= 0 || offset + entrySize > len)
            {
                break;
            }

            if (relation == LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore && entrySize >= 16)
            {
                coreCount++;
                // В структуре PROCESSOR_RELATIONSHIP по смещению +9 находится EfficiencyClass (>0 = P-Core на гибридных Intel)
                var efficiencyClass = raw[offset + 9];
                if (efficiencyClass > 0)
                    highEffCount++;
                else
                    baseEffCount++;
            }
            else if (relation == LOGICAL_PROCESSOR_RELATIONSHIP.RelationCache && entrySize >= 24)
            {
                // CACHE_RELATIONSHIP: +8 Level (byte), +9 Associativity (byte), +10 LineSize (ushort), +12 CacheSize (uint)
                var level = raw[offset + 8];
                var cacheSize = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(offset + 12, 4));
                switch (level)
                {
                    case 1: l1Bytes += cacheSize; break;
                    case 2: l2Bytes += cacheSize; break;
                    case 3: l3Bytes = Math.Max(l3Bytes, cacheSize); break;
                }
            }

            offset += entrySize;
        }

        if (coreCount > 0)
        {
            physicalCores = coreCount;
            if (highEffCount > 0 && baseEffCount > 0)
            {
                pCores = highEffCount;
                eCores = baseEffCount;
            }
            else
            {
                pCores = coreCount;
                eCores = 0;
            }
        }
    }

    // ==================== 3. MEMORY SUBSYSTEM ====================
    private static MemorySubsystemInfo BuildMemorySubsystem(IReadOnlyList<MemoryModuleSlotInfo> smbiosSlots)
    {
        long totalPhys = 0;
        long availPhys = 0;

        if (OperatingSystem.IsWindows())
        {
            var memStatus = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref memStatus))
            {
                totalPhys = (long)memStatus.ullTotalPhys;
                availPhys = (long)memStatus.ullAvailPhys;
            }
        }

        var populated = smbiosSlots.Where(s => s.IsPopulated).ToList();
        if (totalPhys == 0 && populated.Count > 0)
        {
            totalPhys = populated.Sum(s => s.CapacityBytes);
        }

        var configuredSpeed = populated.Count > 0 ? populated.Min(s => s.ConfiguredSpeedMtPerSec) : 0;
        var ratedSpeed = populated.Count > 0 ? populated.Max(s => s.RatedSpeedMtPerSec) : 0;
        var gen = populated.FirstOrDefault()?.MemoryType ?? "DRAM";
        var multiChannel = SmbiosBinaryParser.InferMultiChannelTopology(smbiosSlots);

        return new MemorySubsystemInfo(
            TotalPhysicalBytes: totalPhys,
            AvailablePhysicalBytes: availPhys,
            ConfiguredSpeedMtPerSec: configuredSpeed,
            MaxRatedSpeedMtPerSec: ratedSpeed,
            MemoryGeneration: gen,
            PopulatedSlotsCount: populated.Count,
            TotalSlotsCount: smbiosSlots.Count,
            IsDualOrMultiChannelActive: multiChannel,
            Modules: smbiosSlots);
    }

    // ==================== 4. GPU + DYNAMIC NVML ====================
    private static IReadOnlyList<GpuHardwareInfo> QueryGpuInventory()
    {
        var list = new List<GpuHardwareInfo>();
        if (!OperatingSystem.IsWindows())
        {
            return list;
        }

        var nvmlTelemetry = TryQueryNvidiaNvmlTelemetry();
        var nvmlIndex = 0;

        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}");
            if (classKey is null)
            {
                return list;
            }

            foreach (var subName in classKey.GetSubKeyNames())
            {
                if (subName.Length != 4 || !char.IsDigit(subName[0]))
                {
                    continue;
                }

                using var gpuKey = classKey.OpenSubKey(subName);
                var desc = gpuKey?.GetValue("DriverDesc") as string;
                if (string.IsNullOrWhiteSpace(desc) ||
                    desc.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) ||
                    desc.Contains("Remote Desktop", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var provider = (gpuKey?.GetValue("ProviderName") as string) ?? "GPU";
                var driverVer = (gpuKey?.GetValue("DriverVersion") as string) ?? "";

                // Чтение настоящего 64-битного размера VRAM (без переполнения 4 ГБ в старом WMI!)
                long vramBytes = 0;
                var qwMem = gpuKey?.GetValue("HardwareInformation.qwMemorySize");
                if (qwMem is long qwordLong)
                {
                    vramBytes = qwordLong;
                }
                else if (qwMem is byte[] qwBytes && qwBytes.Length >= 8)
                {
                    vramBytes = BinaryPrimitives.ReadInt64LittleEndian(qwBytes);
                }
                else if (gpuKey?.GetValue("HardwareInformation.MemorySize") is int dwordMem)
                {
                    vramBytes = unchecked((uint)dwordMem);
                }

                bool? rebar = null;
                if (gpuKey?.GetValue("KMD_EnableResizableBar") is int kmdRebar)
                {
                    rebar = kmdRebar != 0;
                }

                double? tempC = null, powerW = null;
                int? fanPct = null, loadPct = null, curGen = null, maxGen = null, curLanes = null, maxLanes = null;

                if ((desc.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) ||
                     provider.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)) &&
                    nvmlIndex < nvmlTelemetry.Count)
                {
                    var nv = nvmlTelemetry[nvmlIndex++];
                    tempC = nv.TempC;
                    fanPct = nv.FanPercent;
                    powerW = nv.PowerWatts;
                    loadPct = nv.GpuLoadPercent;
                    curGen = nv.CurrentPcieGen;
                    maxGen = nv.MaxPcieGen;
                    curLanes = nv.CurrentPcieWidth;
                    maxLanes = nv.MaxPcieWidth;
                    if (nv.ResizableBarDetected.HasValue)
                    {
                        rebar = nv.ResizableBarDetected;
                    }
                }

                list.Add(new GpuHardwareInfo(
                    Index: list.Count,
                    Name: desc,
                    Vendor: provider,
                    DedicatedVramBytes: vramBytes,
                    DriverVersion: driverVer,
                    CurrentPcieGen: curGen,
                    MaxPcieGen: maxGen,
                    CurrentPcieLanes: curLanes,
                    MaxPcieLanes: maxLanes,
                    IsResizableBarEnabled: rebar,
                    CoreTemperatureC: tempC,
                    HotspotTemperatureC: null,
                    MemoryTemperatureC: null,
                    FanSpeedPercent: fanPct,
                    PowerDrawWatts: powerW,
                    CoreLoadPercent: loadPct));
            }
        }
        catch
        {
            // Возвращаем собранный список при частичном отказе доступа к реестру
        }

        return list;
    }

    private sealed record NvmlDeviceSample(
        double? TempC,
        int? FanPercent,
        double? PowerWatts,
        int? GpuLoadPercent,
        int? CurrentPcieGen,
        int? MaxPcieGen,
        int? CurrentPcieWidth,
        int? MaxPcieWidth,
        bool? ResizableBarDetected);

    private static List<NvmlDeviceSample> TryQueryNvidiaNvmlTelemetry()
    {
        var results = new List<NvmlDeviceSample>();
        if (!OperatingSystem.IsWindows())
        {
            return results;
        }

        if (!NativeLibrary.TryLoad("nvml.dll", out var lib))
        {
            return results;
        }

        try
        {
            var init = Marshal.GetDelegateForFunctionPointer<NvmlInitDelegate>(NativeLibrary.GetExport(lib, "nvmlInit_v2"));
            var shutdown = Marshal.GetDelegateForFunctionPointer<NvmlShutdownDelegate>(NativeLibrary.GetExport(lib, "nvmlShutdown"));
            var getCount = Marshal.GetDelegateForFunctionPointer<NvmlGetCountDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetCount_v2"));
            var getHandle = Marshal.GetDelegateForFunctionPointer<NvmlGetHandleDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetHandleByIndex_v2"));
            var getTemp = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntArgDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetTemperature"));
            var getFan = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntOutDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetFanSpeed"));
            var getPower = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntOutDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetPowerUsage"));
            var getUtil = Marshal.GetDelegateForFunctionPointer<NvmlGetUtilDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetUtilizationRates"));
            var getCurrWidth = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntOutDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetCurrPcieLinkWidth"));
            var getMaxWidth = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntOutDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetMaxPcieLinkWidth"));
            var getCurrGen = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntOutDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetCurrPcieLinkGeneration"));
            var getMaxGen = Marshal.GetDelegateForFunctionPointer<NvmlGetUIntOutDelegate>(NativeLibrary.GetExport(lib, "nvmlDeviceGetMaxPcieLinkGeneration"));

            if (init() != 0)
            {
                return results;
            }

            try
            {
                if (getCount(out var count) != 0)
                {
                    return results;
                }

                for (uint i = 0; i < count; i++)
                {
                    if (getHandle(i, out var dev) != 0)
                    {
                        continue;
                    }

                    double? tempC = getTemp(dev, 0, out var t) == 0 ? t : null;
                    int? fan = getFan(dev, out var f) == 0 ? (int)f : null;
                    double? powerW = getPower(dev, out var mw) == 0 ? Math.Round(mw / 1000.0, 1) : null;
                    int? load = getUtil(dev, out var util) == 0 ? (int)util.gpu : null;
                    int? cw = getCurrWidth(dev, out var curW) == 0 ? (int)curW : null;
                    int? mwMax = getMaxWidth(dev, out var maxW) == 0 ? (int)maxW : null;
                    int? cg = getCurrGen(dev, out var curG) == 0 ? (int)curG : null;
                    int? mg = getMaxGen(dev, out var maxG) == 0 ? (int)maxG : null;

                    bool? rebar = null;
                    if (NativeLibrary.TryGetExport(lib, "nvmlDeviceGetBAR1MemoryInfo", out var barExport))
                    {
                        var getBar1 = Marshal.GetDelegateForFunctionPointer<NvmlGetBar1Delegate>(barExport);
                        if (getBar1(dev, out var bar1) == 0 && bar1.bar1Total > 0)
                        {
                            // Стандартное окно BAR1 без Resizable BAR = 256 МБ; при активном ReBAR >= 512 МБ (обычно равно VRAM)
                            rebar = bar1.bar1Total > 512UL * 1024UL * 1024UL;
                        }
                    }

                    results.Add(new NvmlDeviceSample(tempC, fan, powerW, load, cg, mg, cw, mwMax, rebar));
                }
            }
            finally
            {
                _ = shutdown();
            }
        }
        catch
        {
            // Безопасная деградация при нестандартной версии nvml.dll
        }
        finally
        {
            NativeLibrary.Free(lib);
        }

        return results;
    }

    // ==================== 5. STORAGE & NVMe S.M.A.R.T. ====================
    private static IReadOnlyList<StorageDriveSmartInfo> QueryStorageDrives()
    {
        var drives = new List<StorageDriveSmartInfo>();
        if (!OperatingSystem.IsWindows())
        {
            return drives;
        }

        for (var idx = 0; idx < 16; idx++)
        {
            var devicePath = $@"\\.\PhysicalDrive{idx}";
            // dwDesiredAccess = 0 позволяет опрашивать паспорт диска и длину даже без прав Администратора!
            using var handle = CreateFileW(
                devicePath,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                continue;
            }

            if (!TryQueryStorageDescriptor(handle, out var model, out var serial, out var firmware, out var busType))
            {
                continue;
            }

            var capacity = QueryDiskLengthBytes(handle);
            var incursSeekPenalty = QueryIncursSeekPenalty(handle);

            var busKind = busType switch
            {
                0x11 => StorageBusKind.Nvme, // BusTypeNvme
                0x07 => StorageBusKind.UsbExternal, // BusTypeUsb
                _ => incursSeekPenalty == true ? StorageBusKind.HardDiskDrive : StorageBusKind.SataSsd
            };

            NvmeSmartMetrics? nvmeMetrics = null;
            if (busKind == StorageBusKind.Nvme)
            {
                nvmeMetrics = TryQueryNvmeHealthLogIoctl(devicePath);
            }

            drives.Add(new StorageDriveSmartInfo(
                DriveIndex: idx,
                Model: model,
                SerialNumber: serial,
                FirmwareRevision: firmware,
                BusKind: busKind,
                CapacityBytes: capacity,
                IsHealthy: nvmeMetrics?.IsHealthy ?? true,
                RemainingLifePercent: nvmeMetrics?.RemainingLifePercent,
                TemperatureC: nvmeMetrics?.TemperatureC,
                TotalHostReadsTb: nvmeMetrics?.TotalHostReadsTb,
                TotalBytesWrittenTb: nvmeMetrics?.TotalBytesWrittenTb,
                PowerOnHours: nvmeMetrics?.PowerOnHours,
                PowerCycles: nvmeMetrics?.PowerCycles,
                UnsafeShutdowns: nvmeMetrics?.UnsafeShutdowns,
                MediaIntegrityErrors: nvmeMetrics?.MediaIntegrityErrors,
                ReallocatedSectors: null,
                UltraDmaCrcErrors: null));
        }

        return drives;
    }

    private static bool TryQueryStorageDescriptor(
        SafeFileHandle handle,
        out string model,
        out string serial,
        out string firmware,
        out byte busType)
    {
        model = "";
        serial = "";
        firmware = "";
        busType = 0;

        Span<byte> query = stackalloc byte[12]; // STORAGE_PROPERTY_QUERY (PropertyId=0, QueryType=0)
        query.Clear();
        var outBuf = new byte[1024];

        unsafe
        {
            fixed (byte* pIn = query)
            fixed (byte* pOut = outBuf)
            {
                if (!DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        (IntPtr)pIn,
                        (uint)query.Length,
                        (IntPtr)pOut,
                        (uint)outBuf.Length,
                        out var returned,
                        IntPtr.Zero) || returned < 32)
                {
                    return false;
                }
            }
        }

        var vendorOffset = BinaryPrimitives.ReadUInt32LittleEndian(outBuf.AsSpan(12, 4));
        var productOffset = BinaryPrimitives.ReadUInt32LittleEndian(outBuf.AsSpan(16, 4));
        var revOffset = BinaryPrimitives.ReadUInt32LittleEndian(outBuf.AsSpan(20, 4));
        var serialOffset = BinaryPrimitives.ReadUInt32LittleEndian(outBuf.AsSpan(24, 4));
        busType = outBuf[28];

        var vendor = ReadNullTerminatedAscii(outBuf, (int)vendorOffset);
        var product = ReadNullTerminatedAscii(outBuf, (int)productOffset);
        firmware = ReadNullTerminatedAscii(outBuf, (int)revOffset);
        serial = ReadNullTerminatedAscii(outBuf, (int)serialOffset);

        model = string.IsNullOrWhiteSpace(vendor)
            ? product
            : $"{vendor} {product}".Trim();

        if (string.IsNullOrWhiteSpace(model))
        {
            model = "Physical Disk";
        }

        return true;
    }

    private static long QueryDiskLengthBytes(SafeFileHandle handle)
    {
        Span<byte> outBuf = stackalloc byte[8];
        unsafe
        {
            fixed (byte* pOut = outBuf)
            {
                if (DeviceIoControl(
                        handle,
                        IOCTL_DISK_GET_LENGTH_INFO,
                        IntPtr.Zero,
                        0,
                        (IntPtr)pOut,
                        8,
                        out var returned,
                        IntPtr.Zero) && returned >= 8)
                {
                    return BinaryPrimitives.ReadInt64LittleEndian(outBuf);
                }
            }
        }

        return 0;
    }

    private static bool? QueryIncursSeekPenalty(SafeFileHandle handle)
    {
        Span<byte> query = stackalloc byte[12];
        query.Clear();
        BinaryPrimitives.WriteInt32LittleEndian(query[..4], 7); // StorageDeviceSeekPenaltyProperty = 7
        Span<byte> outBuf = stackalloc byte[12];
        outBuf.Clear();

        unsafe
        {
            fixed (byte* pIn = query)
            fixed (byte* pOut = outBuf)
            {
                if (DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        (IntPtr)pIn,
                        (uint)query.Length,
                        (IntPtr)pOut,
                        (uint)outBuf.Length,
                        out var returned,
                        IntPtr.Zero) && returned >= 9)
                {
                    return outBuf[8] != 0;
                }
            }
        }

        return null;
    }

    private static NvmeSmartMetrics? TryQueryNvmeHealthLogIoctl(string devicePath)
    {
        using var handle = CreateFileW(
            devicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            return null;
        }

        // STORAGE_PROPERTY_QUERY (8 байт до AdditionalParameters) + STORAGE_PROTOCOL_SPECIFIC_DATA (40 байт) + 512 байт NVMe Health Log = 560 байт
        const int headerSize = 48;
        const int logSize = 512;
        var buffer = new byte[headerSize + logSize];

        // StorageAdapterProtocolSpecificProperty = 49 (или StorageDeviceProtocolSpecificProperty = 50)
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(0, 4), 49);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(4, 4), 0); // PropertyStandardQuery

        // STORAGE_PROTOCOL_SPECIFIC_DATA начинается со смещения 8:
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(8, 4), 3);  // ProtocolTypeNvme = 3
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(12, 4), 2); // NVMeDataTypeLogPage = 2
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(16, 4), 0x02); // NVME_LOG_PAGE_HEALTH_INFO = 0x02
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(20, 4), 0xFFFFFFFFu); // Global namespace
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(24, 4), 40); // ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(28, 4), logSize); // ProtocolDataLength = 512

        unsafe
        {
            fixed (byte* pBuf = buffer)
            {
                if (!DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        (IntPtr)pBuf,
                        (uint)buffer.Length,
                        (IntPtr)pBuf,
                        (uint)buffer.Length,
                        out var returned,
                        IntPtr.Zero) || returned < headerSize + 176)
                {
                    return null;
                }
            }
        }

        return SmartBinaryParser.TryParseNvmeHealthLog(buffer.AsSpan(headerSize, logSize));
    }

    // ==================== 6. MONITORS & EDID ====================
    private static IReadOnlyList<DisplayMonitorInfo> QueryDisplaysAndEdid()
    {
        var monitors = new List<DisplayMonitorInfo>();
        if (!OperatingSystem.IsWindows())
        {
            return monitors;
        }

        var edidProfiles = ReadAllRegistryEdidProfiles();
        var edidIndex = 0;

        for (uint devIdx = 0; devIdx < 16; devIdx++)
        {
            var adapter = new DISPLAY_DEVICEW { cb = Marshal.SizeOf<DISPLAY_DEVICEW>() };
            if (!EnumDisplayDevicesW(null, devIdx, ref adapter, 0))
            {
                break;
            }

            if ((adapter.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == 0)
            {
                continue;
            }

            var currentMode = CreateDevMode();
            if (!EnumDisplaySettingsExW(adapter.DeviceName, ENUM_CURRENT_SETTINGS, ref currentMode, 0))
            {
                continue;
            }

            var curW = currentMode.dmPelsWidth;
            var curH = currentMode.dmPelsHeight;
            var curHz = currentMode.dmDisplayFrequency;
            var maxHz = curHz;

            // Сканируем все поддерживаемые частоты обновления на текущем нативном разрешении
            for (var modeIdx = 0; modeIdx < 512; modeIdx++)
            {
                var candidate = CreateDevMode();
                if (!EnumDisplaySettingsExW(adapter.DeviceName, modeIdx, ref candidate, 0))
                {
                    break;
                }

                if (candidate.dmPelsWidth == curW &&
                    candidate.dmPelsHeight == curH &&
                    candidate.dmDisplayFrequency > maxHz)
                {
                    maxHz = candidate.dmDisplayFrequency;
                }
            }

            EdidParsedProfile? edid = edidIndex < edidProfiles.Count ? edidProfiles[edidIndex++] : null;
            if (edid is not null && edid.EdidMaxRefreshHz > maxHz)
            {
                // Если EDID заявляет частоту выше только на нативном разрешении — учитываем при совпадении разрешения
                if (edid.PreferredWidthPx == curW && edid.PreferredHeightPx == curH)
                {
                    maxHz = Math.Max(maxHz, edid.EdidMaxRefreshHz);
                }
            }

            monitors.Add(new DisplayMonitorInfo(
                GdiDeviceName: adapter.DeviceName,
                FriendlyModelName: edid?.MonitorName ?? adapter.DeviceString,
                ManufacturerCode: edid?.ManufacturerCode ?? "PNP",
                ManufactureYear: edid?.ManufactureYear,
                NativeWidthPx: curW,
                NativeHeightPx: curH,
                CurrentRefreshHz: curHz,
                MaxSupportedRefreshHz: maxHz,
                ColorBitDepth: edid?.ColorBitDepth,
                DiagonalInches: edid?.DiagonalInches));
        }

        return monitors;
    }

    private static List<EdidParsedProfile> ReadAllRegistryEdidProfiles()
    {
        var result = new List<EdidParsedProfile>();
        try
        {
            using var displayRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\DISPLAY");
            if (displayRoot is null)
            {
                return result;
            }

            foreach (var modelKeyName in displayRoot.GetSubKeyNames())
            {
                using var modelKey = displayRoot.OpenSubKey(modelKeyName);
                if (modelKey is null) continue;

                foreach (var instanceName in modelKey.GetSubKeyNames())
                {
                    using var devParams = modelKey.OpenSubKey($@"{instanceName}\Device Parameters");
                    if (devParams?.GetValue("EDID") is byte[] rawEdid)
                    {
                        var parsed = EdidBinaryParser.TryParse(rawEdid);
                        if (parsed is not null)
                        {
                            result.Add(parsed);
                        }
                    }
                }
            }
        }
        catch
        {
            // Безопасный пропуск при ограничениях доступа
        }

        return result;
    }

    // ==================== 7. BATTERY & POWER PLAN ====================
    private static BatteryHealthInfo QueryBatteryStatus()
    {
        if (!OperatingSystem.IsWindows() || !GetSystemPowerStatus(out var sps))
        {
            return new BatteryHealthInfo(false, true, 100, null, null);
        }

        var hasBattery = (sps.BatteryFlag & 128) == 0 && sps.BatteryFlag != 255;
        var onAc = sps.ACLineStatus == 1;
        var pct = sps.BatteryLifePercent <= 100 ? sps.BatteryLifePercent : 100;

        return new BatteryHealthInfo(
            IsPresent: hasBattery,
            IsOnAcPower: onAc,
            ChargePercent: pct,
            DesignCapacityMwh: null,
            FullChargeCapacityMwh: null);
    }

    private static PowerPlanInfo QueryActivePowerPlan()
    {
        var guid = GetActivePowerSchemeGuidOrDefault();
        var name = guid == PowerSaverGuid ? "Экономия энергии"
            : guid == HighPerformanceGuid ? "Высокая производительность"
            : guid == UltimatePerformanceGuid ? "Максимальная производительность"
            : "Сбалансированная";

        return new PowerPlanInfo(
            SchemeGuid: guid,
            FriendlyName: name,
            IsPowerSaver: guid == PowerSaverGuid,
            IsHighOrUltimatePerformance: guid == HighPerformanceGuid || guid == UltimatePerformanceGuid);
    }

    private static Guid GetActivePowerSchemeGuidOrDefault()
    {
        if (!OperatingSystem.IsWindows())
        {
            return BalancedGuid;
        }

        if (PowerGetActiveScheme(IntPtr.Zero, out var ptrGuid) == 0 && ptrGuid != IntPtr.Zero)
        {
            try
            {
                return Marshal.PtrToStructure<Guid>(ptrGuid);
            }
            finally
            {
                LocalFree(ptrGuid);
            }
        }

        return BalancedGuid;
    }

    private static string ReadNullTerminatedAscii(byte[] buffer, int offset)
    {
        if (offset <= 0 || offset >= buffer.Length)
        {
            return "";
        }

        var end = offset;
        while (end < buffer.Length && buffer[end] != 0)
        {
            end++;
        }

        return Encoding.ASCII.GetString(buffer, offset, end - offset).Trim();
    }

    private static DEVMODEW CreateDevMode() => new()
    {
        dmDeviceName = string.Empty,
        dmFormName = string.Empty,
        dmSize = (ushort)Marshal.SizeOf<DEVMODEW>()
    };

    // ==================== WIN32 P/INVOKE DEFINITIONS ====================
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;
    private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    private const uint IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C;

    private const int ENUM_CURRENT_SETTINGS = -1;
    private const int DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x00000001;
    private const int DM_DISPLAYFREQUENCY = 0x00400000;
    private const uint CDS_UPDATEREGISTRY = 0x00000001;
    private const uint CDS_TEST = 0x00000002;
    private const int DISP_CHANGE_SUCCESSFUL = 0;

    private enum LOGICAL_PROCESSOR_RELATIONSHIP
    {
        RelationProcessorCore = 0,
        RelationNumaNode = 1,
        RelationCache = 2,
        RelationProcessorPackage = 3,
        RelationGroup = 4,
        RelationAll = 0xFFFF
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetSystemFirmwareTable(
        uint FirmwareTableProviderSignature,
        uint FirmwareTableID,
        IntPtr pFirmwareTableBuffer,
        uint BufferSize);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLogicalProcessorInformationEx(
        LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType,
        IntPtr Buffer,
        ref uint ReturnedLength);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("powrprof.dll", ExactSpelling = true)]
    private static extern uint PowerGetActiveScheme(IntPtr UserRootPowerKey, out IntPtr ActivePolicyGuid);

    [DllImport("powrprof.dll", ExactSpelling = true)]
    private static extern uint PowerSetActiveScheme(IntPtr UserRootPowerKey, ref Guid SchemeGuid);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplayDevicesW(
        string? lpDevice,
        uint iDevNum,
        ref DISPLAY_DEVICEW lpDisplayDevice,
        uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplaySettingsExW(
        string lpszDeviceName,
        int iModeNum,
        ref DEVMODEW lpDevMode,
        uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int ChangeDisplaySettingsExW(
        string lpszDeviceName,
        ref DEVMODEW lpDevMode,
        IntPtr hwnd,
        uint dwflags,
        IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DISPLAY_DEVICEW
    {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DEVMODEW
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmDeviceName;
        public ushort dmSpecVersion;
        public ushort dmDriverVersion;
        public ushort dmSize;
        public ushort dmDriverExtra;
        public int dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public int dmDisplayOrientation;
        public int dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmFormName;
        public ushort dmLogPixels;
        public int dmBitsPerPel;
        public int dmPelsWidth;
        public int dmPelsHeight;
        public int dmDisplayFlags;
        public int dmDisplayFrequency;
        public int dmICMMethod;
        public int dmICMIntent;
        public int dmMediaType;
        public int dmDitherType;
        public int dmReserved1;
        public int dmReserved2;
        public int dmPanningWidth;
        public int dmPanningHeight;
    }

    // Делегаты динамического вызова NVIDIA NVML (nvml.dll)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlInitDelegate();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlShutdownDelegate();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlGetCountDelegate(out uint deviceCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlGetHandleDelegate(uint index, out IntPtr device);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlGetUIntArgDelegate(IntPtr device, uint sensorType, out uint value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlGetUIntOutDelegate(IntPtr device, out uint value);

    [StructLayout(LayoutKind.Sequential)]
    private struct NvmlUtilization
    {
        public uint gpu;
        public uint memory;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlGetUtilDelegate(IntPtr device, out NvmlUtilization utilization);

    [StructLayout(LayoutKind.Sequential)]
    private struct NvmlBar1Memory
    {
        public ulong bar1Total;
        public ulong bar1Free;
        public ulong bar1Used;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int NvmlGetBar1Delegate(IntPtr device, out NvmlBar1Memory bar1Memory);
}
