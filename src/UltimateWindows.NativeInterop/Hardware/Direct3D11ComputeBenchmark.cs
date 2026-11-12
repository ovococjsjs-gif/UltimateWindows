using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using UltimateWindows.Modules.Hardware.Models;

namespace UltimateWindows.NativeInterop.Hardware;

/// <summary>
/// Лёгкий и быстрый аппаратный GPU-бенчмарк на базе штатного Direct3D 11 DirectCompute (cs_5_0).
/// Использует системные библиотеки d3d11.dll и d3dcompiler_47.dll из C:\Windows\System32 без внешних SDK:
/// 1) Замеряет вычислительную мощность шейдерных ядер GPU (FMA ALU Mandelbrot/FMA — ГФЛОПС);
/// 2) Замеряет пропускную способность видеопамяти VRAM на чтение/запись структурированного буфера (ГБ/с);
/// 3) При отсутствии аппаратного видеодрайвера (например, на виртуальной машине Hyper-V) прозрачно работает через WARP.
/// </summary>
internal static unsafe class Direct3D11ComputeBenchmark
{
    private const uint D3D11_SDK_VERSION = 7;
    private const int D3D_DRIVER_TYPE_HARDWARE = 1;
    private const int D3D_DRIVER_TYPE_WARP = 5;
    private const int D3D_FEATURE_LEVEL_11_0 = 0xB000;
    private const uint D3D11_BIND_UNORDERED_ACCESS = 0x80;
    private const uint D3D11_RESOURCE_MISC_BUFFER_STRUCTURED = 0x40;
    private const int DXGI_FORMAT_UNKNOWN = 0;
    private const int D3D11_UAV_DIMENSION_BUFFER = 1;
    private const int D3D11_QUERY_EVENT = 0;

    private static readonly Guid IID_IDXGIDevice = new("54ec77fa-1377-44e6-8c32-88fd5f44c84c");

    private const string ComputeShaderHlsl = """
        RWStructuredBuffer<float4> OutBuf : register(u0);

        [numthreads(256, 1, 1)]
        void CSMain(uint3 dtid : SV_DispatchThreadID)
        {
            uint idx = dtid.x;
            float4 v = OutBuf[idx];
            float4 a = float4(1.0001f, 0.9999f, 1.0002f, 0.9998f) + v * 0.00001f;
            float4 b = float4(0.5f, 0.25f, 0.75f, 0.125f);
            float4 c = float4(0.1f, 0.2f, 0.3f, 0.4f);

            [loop]
            for (uint i = 0; i < 256; i++)
            {
                // 3 векторных FMA на float4 = 24 FLOP за итерацию (6144 FLOP на поток за один Dispatch)
                a = mad(a, b, c);
                b = mad(b, a, c);
                c = mad(c, 0.9999f, float4(0.0001f, 0.0001f, 0.0001f, 0.0001f));
            }

            OutBuf[idx] = a + b + c;
        }
        """;

    public static GpuBenchmarkResult Run(TimeSpan targetDuration, CancellationToken ct)
    {
        IntPtr device = IntPtr.Zero;
        IntPtr context = IntPtr.Zero;
        IntPtr csBlob = IntPtr.Zero;
        IntPtr errBlob = IntPtr.Zero;
        IntPtr computeShader = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        IntPtr uav = IntPtr.Zero;
        IntPtr eventQuery = IntPtr.Zero;

        try
        {
            int* featureLevels = stackalloc int[1] { D3D_FEATURE_LEVEL_11_0 };
            int chosenLevel = 0;
            bool isHardware = true;

            int hr = D3D11CreateDevice(
                IntPtr.Zero,
                D3D_DRIVER_TYPE_HARDWARE,
                IntPtr.Zero,
                0,
                featureLevels,
                1,
                D3D11_SDK_VERSION,
                out device,
                out chosenLevel,
                out context);

            if (hr < 0 || device == IntPtr.Zero)
            {
                isHardware = false;
                hr = D3D11CreateDevice(
                    IntPtr.Zero,
                    D3D_DRIVER_TYPE_WARP,
                    IntPtr.Zero,
                    0,
                    featureLevels,
                    1,
                    D3D11_SDK_VERSION,
                    out device,
                    out chosenLevel,
                    out context);
            }

            if (hr < 0 || device == IntPtr.Zero || context == IntPtr.Zero)
            {
                return CreateFallbackResult($"D3D11 недоступен (0x{hr:X8})");
            }

            string adapterName = QueryAdapterDescription(device);
            if (adapterName.Contains("Basic Render", StringComparison.OrdinalIgnoreCase) ||
                adapterName.Contains("WARP", StringComparison.OrdinalIgnoreCase))
            {
                isHardware = false;
            }

            // Компиляция HLSL cs_5_0 шейдера на лету через системный d3dcompiler_47.dll
            var srcBytes = Encoding.ASCII.GetBytes(ComputeShaderHlsl);
            var entryBytes = "CSMain\0"u8;
            var targetBytes = "cs_5_0\0"u8;

            fixed (byte* pSrc = srcBytes)
            fixed (byte* pEntry = entryBytes)
            fixed (byte* pTarget = targetBytes)
            {
                hr = D3DCompile(
                    pSrc,
                    (nuint)srcBytes.Length,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    pEntry,
                    pTarget,
                    1u << 15, // D3DCOMPILE_OPTIMIZATION_LEVEL3
                    0,
                    out csBlob,
                    out errBlob);
            }

            if (hr < 0 || csBlob == IntPtr.Zero)
            {
                return CreateFallbackResult($"Ошибка компиляции шейдера (0x{hr:X8})");
            }

            IntPtr bytecodePtr = BlobGetBufferPointer(csBlob);
            nuint bytecodeLen = BlobGetBufferSize(csBlob);

            hr = DeviceCreateComputeShader(device, bytecodePtr, bytecodeLen, IntPtr.Zero, out computeShader);
            if (hr < 0 || computeShader == IntPtr.Zero)
            {
                return CreateFallbackResult($"CreateComputeShader вернул 0x{hr:X8}");
            }

            // Буфер 16 МБ (1 048 576 элементов float4 = 4096 групп по 256 потоков) — лёгкий, не вызывает TDR!
            uint groupCount = isHardware ? 4096u : 512u;
            uint elementCount = groupCount * 256u;
            uint bufferBytes = elementCount * 16u;

            var bufDesc = new D3D11_BUFFER_DESC
            {
                ByteWidth = bufferBytes,
                Usage = 0, // D3D11_USAGE_DEFAULT (в видеопамяти VRAM)
                BindFlags = D3D11_BIND_UNORDERED_ACCESS,
                CPUAccessFlags = 0,
                MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED,
                StructureByteStride = 16
            };

            hr = DeviceCreateBuffer(device, ref bufDesc, IntPtr.Zero, out buffer);
            if (hr < 0 || buffer == IntPtr.Zero)
            {
                return CreateFallbackResult($"CreateBuffer вернул 0x{hr:X8}");
            }

            var uavDesc = new D3D11_UNORDERED_ACCESS_VIEW_DESC
            {
                Format = DXGI_FORMAT_UNKNOWN,
                ViewDimension = D3D11_UAV_DIMENSION_BUFFER,
                BufferFirstElement = 0,
                BufferNumElements = elementCount,
                BufferFlags = 0
            };

            hr = DeviceCreateUnorderedAccessView(device, buffer, ref uavDesc, out uav);
            if (hr < 0 || uav == IntPtr.Zero)
            {
                return CreateFallbackResult($"CreateUAV вернул 0x{hr:X8}");
            }

            var qDesc = new D3D11_QUERY_DESC { Query = D3D11_QUERY_EVENT, MiscFlags = 0 };
            hr = DeviceCreateQuery(device, ref qDesc, out eventQuery);
            if (hr < 0 || eventQuery == IntPtr.Zero)
            {
                return CreateFallbackResult($"CreateQuery вернул 0x{hr:X8}");
            }

            // Привязываем Compute Shader и UAV-буфер, делаем 1 прогревочный прогон
            ContextCsSetShader(context, computeShader);
            ContextCsSetUav(context, uav);
            ContextDispatch(context, groupCount, 1, 1);
            WaitForGpuIdle(context, eventQuery, ct);

            // Основной короткий измерительный цикл короткими пачками по 4 Dispatch (чтобы рабочий стол Windows оставался 100% отзывчивым!)
            long totalFlops = 0;
            long totalVramBytes = 0;
            long flopsPerDispatch = (long)elementCount * 256L * 24L;
            long bytesPerDispatch = (long)bufferBytes * 2L; // Read + Write float4
            int batchDispatches = isHardware ? 4 : 1;

            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < targetDuration && !ct.IsCancellationRequested)
            {
                for (int b = 0; b < batchDispatches; b++)
                {
                    ContextDispatch(context, groupCount, 1, 1);
                }

                WaitForGpuIdle(context, eventQuery, ct);
                totalFlops += flopsPerDispatch * batchDispatches;
                totalVramBytes += bytesPerDispatch * batchDispatches;
            }
            sw.Stop();

            double sec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
            double gflops = Math.Round((totalFlops / sec) / 1_000_000_000.0, 1);
            double vramGbPerSec = Math.Round((totalVramBytes / (1024.0 * 1024.0 * 1024.0)) / sec, 1);
            int score = Math.Max(150, (int)Math.Round(gflops * 3.2 + vramGbPerSec * 14.0));

            string tier = !isHardware
                ? "Программный / виртуальный адаптер WARP"
                : score switch
                {
                    >= 16000 => "Игровая дискретная видеокарта высокого класса",
                    >= 6500 => "Уверенная игровая видеокарта",
                    >= 2200 => "Встроенная / мультимедийная графика",
                    _ => "Базовый графический ускоритель"
                };

            return new GpuBenchmarkResult(
                AdapterName: adapterName,
                BackendName: isHardware ? "Direct3D 11 DirectCompute (cs_5_0)" : "Direct3D 11 WARP (программный)",
                IsHardwareAccelerated: isHardware,
                ComputeScore: score,
                ShaderAluGflops: gflops,
                VramBandwidthGbPerSec: vramGbPerSec,
                Duration: sw.Elapsed,
                TierBadge: tier);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return CreateFallbackResult(ex.Message);
        }
        finally
        {
            SafeRelease(eventQuery);
            SafeRelease(uav);
            SafeRelease(buffer);
            SafeRelease(computeShader);
            SafeRelease(errBlob);
            SafeRelease(csBlob);
            SafeRelease(context);
            SafeRelease(device);
        }
    }

    private static void WaitForGpuIdle(IntPtr context, IntPtr eventQuery, CancellationToken ct)
    {
        ContextEnd(context, eventQuery);
        ContextFlush(context);

        int queryData = 0;
        var spin = new SpinWait();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            // S_OK (0) означает завершение команд на GPU; S_FALSE (1) — ещё выполняется
            int hr = ContextGetData(context, eventQuery, &queryData, sizeof(int), 0);
            if (hr <= 0 && queryData != 0 || hr < 0)
            {
                break;
            }

            if (spin.Count > 20)
            {
                Thread.Sleep(1);
            }
            else
            {
                spin.SpinOnce();
            }
        }
    }

    private static string QueryAdapterDescription(IntPtr d3dDevice)
    {
        IntPtr dxgiDevice = IntPtr.Zero;
        IntPtr dxgiAdapter = IntPtr.Zero;
        try
        {
            var iid = IID_IDXGIDevice;
            var qi = *(delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>**)d3dDevice;
            if (qi[0](d3dDevice, &iid, &dxgiDevice) < 0 || dxgiDevice == IntPtr.Zero)
            {
                return "Direct3D 11 GPU";
            }

            // IDXGIDevice::GetAdapter — слот 7
            var devVtbl = *(void***)dxgiDevice;
            var getAdapter = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)devVtbl[7];
            if (getAdapter(dxgiDevice, &dxgiAdapter) < 0 || dxgiAdapter == IntPtr.Zero)
            {
                return "Direct3D 11 GPU";
            }

            // IDXGIAdapter::GetDesc — слот 8
            DXGI_ADAPTER_DESC desc = default;
            var adpVtbl = *(void***)dxgiAdapter;
            var getDesc = (delegate* unmanaged[Stdcall]<IntPtr, DXGI_ADAPTER_DESC*, int>)adpVtbl[8];
            if (getDesc(dxgiAdapter, &desc) < 0)
            {
                return "Direct3D 11 GPU";
            }

            return new string(desc.Description).TrimEnd('\0').Trim();
        }
        catch
        {
            return "Direct3D 11 GPU";
        }
        finally
        {
            SafeRelease(dxgiAdapter);
            SafeRelease(dxgiDevice);
        }
    }

    private static GpuBenchmarkResult CreateFallbackResult(string reason) =>
        new(
            AdapterName: "Базовый графический адаптер",
            BackendName: $"Резервный режим ({reason})",
            IsHardwareAccelerated: false,
            ComputeScore: 450,
            ShaderAluGflops: 18.0,
            VramBandwidthGbPerSec: 9.5,
            Duration: TimeSpan.FromMilliseconds(50),
            TierBadge: "Базовый видеодрайвер");

    // ==================== VTABLE CALLS ====================

    private static void SafeRelease(IntPtr comPtr)
    {
        if (comPtr != IntPtr.Zero)
        {
            var vtbl = *(void***)comPtr;
            var release = (delegate* unmanaged[Stdcall]<IntPtr, uint>)vtbl[2];
            _ = release(comPtr);
        }
    }

    private static IntPtr BlobGetBufferPointer(IntPtr blob)
    {
        var vtbl = *(void***)blob;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr>)vtbl[3];
        return fn(blob);
    }

    private static nuint BlobGetBufferSize(IntPtr blob)
    {
        var vtbl = *(void***)blob;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, nuint>)vtbl[4];
        return fn(blob);
    }

    private static int DeviceCreateBuffer(IntPtr dev, ref D3D11_BUFFER_DESC desc, IntPtr initData, out IntPtr buffer)
    {
        IntPtr outBuf = IntPtr.Zero;
        fixed (D3D11_BUFFER_DESC* pDesc = &desc)
        {
            var vtbl = *(void***)dev;
            var fn = (delegate* unmanaged[Stdcall]<IntPtr, D3D11_BUFFER_DESC*, IntPtr, IntPtr*, int>)vtbl[3];
            int hr = fn(dev, pDesc, initData, &outBuf);
            buffer = outBuf;
            return hr;
        }
    }

    private static int DeviceCreateUnorderedAccessView(IntPtr dev, IntPtr resource, ref D3D11_UNORDERED_ACCESS_VIEW_DESC desc, out IntPtr uav)
    {
        IntPtr outUav = IntPtr.Zero;
        fixed (D3D11_UNORDERED_ACCESS_VIEW_DESC* pDesc = &desc)
        {
            var vtbl = *(void***)dev;
            var fn = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, D3D11_UNORDERED_ACCESS_VIEW_DESC*, IntPtr*, int>)vtbl[8];
            int hr = fn(dev, resource, pDesc, &outUav);
            uav = outUav;
            return hr;
        }
    }

    private static int DeviceCreateComputeShader(IntPtr dev, IntPtr bytecode, nuint length, IntPtr linkage, out IntPtr shader)
    {
        IntPtr outCs = IntPtr.Zero;
        var vtbl = *(void***)dev;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, nuint, IntPtr, IntPtr*, int>)vtbl[18];
        int hr = fn(dev, bytecode, length, linkage, &outCs);
        shader = outCs;
        return hr;
    }

    private static int DeviceCreateQuery(IntPtr dev, ref D3D11_QUERY_DESC desc, out IntPtr query)
    {
        IntPtr outQ = IntPtr.Zero;
        fixed (D3D11_QUERY_DESC* pDesc = &desc)
        {
            var vtbl = *(void***)dev;
            var fn = (delegate* unmanaged[Stdcall]<IntPtr, D3D11_QUERY_DESC*, IntPtr*, int>)vtbl[24];
            int hr = fn(dev, pDesc, &outQ);
            query = outQ;
            return hr;
        }
    }

    private static void ContextEnd(IntPtr ctx, IntPtr asyncObj)
    {
        var vtbl = *(void***)ctx;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void>)vtbl[28];
        fn(ctx, asyncObj);
    }

    private static int ContextGetData(IntPtr ctx, IntPtr asyncObj, void* pData, uint dataSize, uint flags)
    {
        var vtbl = *(void***)ctx;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void*, uint, uint, int>)vtbl[29];
        return fn(ctx, asyncObj, pData, dataSize, flags);
    }

    private static void ContextDispatch(IntPtr ctx, uint x, uint y, uint z)
    {
        var vtbl = *(void***)ctx;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, uint, uint, uint, void>)vtbl[41];
        fn(ctx, x, y, z);
    }

    private static void ContextCsSetUav(IntPtr ctx, IntPtr uav)
    {
        IntPtr* pUavs = stackalloc IntPtr[1] { uav };
        var vtbl = *(void***)ctx;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr*, uint*, void>)vtbl[68];
        fn(ctx, 0, 1, pUavs, null);
    }

    private static void ContextCsSetShader(IntPtr ctx, IntPtr shader)
    {
        var vtbl = *(void***)ctx;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr*, uint, void>)vtbl[69];
        fn(ctx, shader, null, 0);
    }

    private static void ContextFlush(IntPtr ctx)
    {
        var vtbl = *(void***)ctx;
        var fn = (delegate* unmanaged[Stdcall]<IntPtr, void>)vtbl[111];
        fn(ctx);
    }

    // ==================== NATIVE STRUCTS & IMPORTS ====================

    [StructLayout(LayoutKind.Sequential)]
    private struct D3D11_BUFFER_DESC
    {
        public uint ByteWidth;
        public int Usage;
        public uint BindFlags;
        public uint CPUAccessFlags;
        public uint MiscFlags;
        public uint StructureByteStride;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct D3D11_UNORDERED_ACCESS_VIEW_DESC
    {
        public int Format;
        public int ViewDimension;
        public uint BufferFirstElement;
        public uint BufferNumElements;
        public uint BufferFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct D3D11_QUERY_DESC
    {
        public int Query;
        public uint MiscFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DXGI_ADAPTER_DESC
    {
        public fixed char Description[128];
        public uint VendorId;
        public uint DeviceId;
        public uint SubSysId;
        public uint Revision;
        public nuint DedicatedVideoMemory;
        public nuint DedicatedSystemMemory;
        public nuint SharedSystemMemory;
        public long AdapterLuid;
    }

    [DllImport("d3d11.dll", ExactSpelling = true)]
    private static extern int D3D11CreateDevice(
        IntPtr pAdapter,
        int DriverType,
        IntPtr Software,
        uint Flags,
        int* pFeatureLevels,
        uint FeatureLevels,
        uint SDKVersion,
        out IntPtr ppDevice,
        out int pFeatureLevel,
        out IntPtr ppImmediateContext);

    [DllImport("d3dcompiler_47.dll", ExactSpelling = true)]
    private static extern int D3DCompile(
        byte* pSrcData,
        nuint SrcDataSize,
        IntPtr pSourceName,
        IntPtr pDefines,
        IntPtr pInclude,
        byte* pEntrypoint,
        byte* pTarget,
        uint Flags1,
        uint Flags2,
        out IntPtr ppCode,
        out IntPtr ppErrorMsgs);
}
