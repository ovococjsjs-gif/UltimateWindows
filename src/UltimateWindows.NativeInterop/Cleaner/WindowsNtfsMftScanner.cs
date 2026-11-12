using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using UltimateWindows.Modules.Cleaner.DiskMap;
using UltimateWindows.Modules.Cleaner.Models;
using UltimateWindows.NativeInterop.Security;

namespace UltimateWindows.NativeInterop.Cleaner;

/// <summary>
/// Прямое чтение таблицы файлов NTFS (<c>$MFT</c>) через дескриптор тома <c>\\.\X:</c>.
/// <para>
/// Как работает без гаданий и самодельного разбора runlist:
/// 1) открывает том только на чтение (<c>GENERIC_READ</c>, <c>FILE_SHARE_READ|WRITE|DELETE</c>);
/// 2) через <c>FSCTL_GET_NTFS_VOLUME_DATA</c> узнаёт размер кластера и размер одной записи MFT;
/// 3) открывает системный метафайл <c>X:\$MFT</c> на чтение атрибутов и вызывает <c>FSCTL_GET_RETRIEVAL_POINTERS</c> —
///    драйвер NTFS сам отдаёт точный список физических отрезков (LCN + число кластеров) со всеми фрагментами MFT;
/// 4) читает эти отрезки с тома блоками по 4 МБ и передаёт каждую запись в <see cref="NtfsMftParser.TryParseRecord"/>.
/// </para>
/// <para>
/// Если прав администратора нет, файловая система не NTFS (например, FAT32/exFAT/ReFS) или драйвер отказал —
/// метод возвращает <c>null</c>, и <see cref="FastDiskSpaceAnalyzer"/> прозрачно переходит на многопоточный обход папок.
/// </para>
/// </summary>
internal static class WindowsNtfsMftScanner
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_READ_ATTRIBUTES = 0x00000080;
    private const uint FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;
    private const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
    private const int ERROR_MORE_DATA = 234;

    private const int ReadChunkBytes = 4 * 1024 * 1024; // 4 МБ за один ReadFile

    public static DiskSpaceAnalysisReport? TryScanNtfsVolume(
        string targetPath,
        int topDirectoryLimit,
        int largestFilesLimit,
        CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || !ElevationChecker.IsRunningAsAdministrator())
        {
            return null;
        }

        string fullTarget;
        try
        {
            fullTarget = Path.GetFullPath(targetPath);
        }
        catch
        {
            return null;
        }

        if (fullTarget.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return null; // Сетевой путь UNC
        }

        var root = Path.GetPathRoot(fullTarget);
        if (string.IsNullOrWhiteSpace(root) || root.Length < 2 || !char.IsLetter(root[0]) || root[1] != ':')
        {
            return null;
        }

        try
        {
            var di = new DriveInfo(root[..1]);
            if (!di.IsReady || !string.Equals(di.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
        }
        catch
        {
            return null;
        }

        var drivePrefix = $"{char.ToUpperInvariant(root[0])}:";
        var volumeDevicePath = $@"\\.\{drivePrefix}";
        var mftFilePath = $@"\\.\{drivePrefix}\$MFT";

        var sw = Stopwatch.StartNew();

        using var volumeHandle = CreateFileW(
            volumeDevicePath,
            GENERIC_READ,
            FILE_SHARE_ALL,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (volumeHandle.IsInvalid)
        {
            return null;
        }

        if (!TryQueryNtfsVolumeData(volumeHandle, out var volData))
        {
            return null;
        }

        int bytesPerCluster = (int)volData.BytesPerCluster;
        int bytesPerRecord = (int)volData.BytesPerFileRecordSegment;
        if (bytesPerCluster is < 512 or > 65536 ||
            bytesPerRecord is < 512 or > 65536 ||
            bytesPerRecord % 512 != 0)
        {
            return null;
        }

        var extents = QueryMftExtents(mftFilePath, volData);
        if (extents.Count == 0)
        {
            return null;
        }

        var estimatedRecords = (int)Math.Clamp(volData.MftValidDataLength / bytesPerRecord, 1024, 8_000_000);
        var entries = new List<NtfsMftEntry>(Math.Min(estimatedRecords, 512_000));

        var buffer = ArrayPool<byte>.Shared.Rent(ReadChunkBytes);
        try
        {
            ulong currentRecordNumber = 0;
            int alignChunk = (ReadChunkBytes / bytesPerRecord) * bytesPerRecord;

            foreach (var (lcn, clusterCount) in extents)
            {
                ct.ThrowIfCancellationRequested();

                if (lcn < 0 || clusterCount <= 0)
                {
                    // Разреженный участок (в $MFT практически не встречается, но учитываем смещение номеров записей)
                    var skippedBytes = clusterCount * (long)bytesPerCluster;
                    currentRecordNumber += (ulong)(skippedBytes / bytesPerRecord);
                    continue;
                }

                long diskOffset = lcn * (long)bytesPerCluster;
                long remaining = clusterCount * (long)bytesPerCluster;

                while (remaining >= bytesPerRecord)
                {
                    ct.ThrowIfCancellationRequested();

                    int toRead = (int)Math.Min(alignChunk, remaining);
                    // ReadFile по дескриптору тома требует кратности размеру сектора (bytesPerRecord уже кратен 512)
                    toRead = (toRead / bytesPerRecord) * bytesPerRecord;
                    if (toRead <= 0)
                    {
                        break;
                    }

                    if (!SeekAndRead(volumeHandle, diskOffset, buffer.AsSpan(0, toRead), out int actualRead) ||
                        actualRead < bytesPerRecord)
                    {
                        return null;
                    }

                    int fullRecordsBytes = (actualRead / bytesPerRecord) * bytesPerRecord;
                    for (int off = 0; off < fullRecordsBytes; off += bytesPerRecord)
                    {
                        var recSpan = buffer.AsSpan(off, bytesPerRecord);
                        if (NtfsMftParser.TryParseRecord(recSpan, currentRecordNumber, out var parsed))
                        {
                            entries.Add(parsed);
                        }

                        currentRecordNumber++;
                    }

                    diskOffset += fullRecordsBytes;
                    remaining -= fullRecordsBytes;

                    if (fullRecordsBytes == 0)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        sw.Stop();
        if (entries.Count == 0)
        {
            return null;
        }

        var method = $"Прямое чтение NTFS $MFT ({extents.Count} экстент(ов), запись {bytesPerRecord} Б)";
        return NtfsMftParser.BuildReportFromEntries(
            entries,
            volumeRoot: drivePrefix + Path.DirectorySeparatorChar,
            targetFullPath: fullTarget,
            methodDescription: method,
            elapsed: sw.Elapsed,
            topDirectoryLimit: topDirectoryLimit,
            largestFilesLimit: largestFilesLimit,
            ct: ct);
    }

    private static List<(long Lcn, long ClusterCount)> QueryMftExtents(
        string mftFilePath,
        NTFS_VOLUME_DATA_BUFFER volData)
    {
        using var mftHandle = CreateFileW(
            mftFilePath,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        if (!mftHandle.IsInvalid)
        {
            var fromDriver = ReadRetrievalPointers(mftHandle);
            if (fromDriver.Count > 0)
            {
                return fromDriver;
            }
        }

        // Запасной вариант для нефрагментированного MFT (например, свежесозданный том): стартовый LCN из NTFS_VOLUME_DATA_BUFFER
        if (volData.MftStartLcn > 0 && volData.MftValidDataLength > 0 && volData.BytesPerCluster > 0)
        {
            var clusters = (volData.MftValidDataLength + volData.BytesPerCluster - 1) / volData.BytesPerCluster;
            if (clusters > 0)
            {
                return [(volData.MftStartLcn, clusters)];
            }
        }

        return [];
    }

    private static unsafe List<(long Lcn, long ClusterCount)> ReadRetrievalPointers(SafeFileHandle mftHandle)
    {
        var result = new List<(long Lcn, long ClusterCount)>();
        long startVcn = 0;
        byte[] outBuf = new byte[64 * 1024];

        while (true)
        {
            long inputStartingVcn = startVcn;
            bool ok;
            uint returned;

            fixed (byte* pOut = outBuf)
            {
                ok = DeviceIoControl(
                    mftHandle,
                    FSCTL_GET_RETRIEVAL_POINTERS,
                    &inputStartingVcn,
                    sizeof(long),
                    pOut,
                    (uint)outBuf.Length,
                    out returned,
                    IntPtr.Zero);
            }

            int lastErr = Marshal.GetLastWin32Error();
            if (!ok && lastErr != ERROR_MORE_DATA)
            {
                break;
            }

            if (returned < 32)
            {
                break;
            }

            // RETRIEVAL_POINTERS_BUFFER (64-bit выравнивание):
            // [0..4]   DWORD ExtentCount
            // [4..8]   padding
            // [8..16]  LARGE_INTEGER StartingVcn
            // [16..]   массив пар { LARGE_INTEGER NextVcn; LARGE_INTEGER Lcn; } по 16 байт
            uint extentCount = BinaryPrimitives.ReadUInt32LittleEndian(outBuf.AsSpan(0, 4));
            long prevVcn = BinaryPrimitives.ReadInt64LittleEndian(outBuf.AsSpan(8, 8));

            int maxPossible = (int)((returned - 16) / 16);
            int count = (int)Math.Min(extentCount, (uint)Math.Max(0, maxPossible));
            if (count == 0)
            {
                break;
            }

            for (int i = 0; i < count; i++)
            {
                int pos = 16 + i * 16;
                long nextVcn = BinaryPrimitives.ReadInt64LittleEndian(outBuf.AsSpan(pos, 8));
                long lcn = BinaryPrimitives.ReadInt64LittleEndian(outBuf.AsSpan(pos + 8, 8));
                long clusters = nextVcn - prevVcn;
                if (clusters > 0)
                {
                    result.Add((lcn, clusters));
                }

                prevVcn = nextVcn;
            }

            if (ok)
            {
                break;
            }

            startVcn = prevVcn;
        }

        return result;
    }

    private static unsafe bool TryQueryNtfsVolumeData(SafeFileHandle volumeHandle, out NTFS_VOLUME_DATA_BUFFER data)
    {
        data = default;
        NTFS_VOLUME_DATA_BUFFER local = default;
        bool ok = DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            null,
            0,
            &local,
            (uint)sizeof(NTFS_VOLUME_DATA_BUFFER),
            out uint returned,
            IntPtr.Zero);

        if (!ok || returned < sizeof(NTFS_VOLUME_DATA_BUFFER))
        {
            return false;
        }

        data = local;
        return true;
    }

    private static unsafe bool SeekAndRead(
        SafeFileHandle handle,
        long offsetBytes,
        Span<byte> destination,
        out int bytesRead)
    {
        bytesRead = 0;
        if (!SetFilePointerEx(handle, offsetBytes, out _, 0))
        {
            return false;
        }

        fixed (byte* pDest = destination)
        {
            if (!ReadFile(handle, pDest, (uint)destination.Length, out uint read, IntPtr.Zero))
            {
                return false;
            }

            bytesRead = (int)read;
            return true;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NTFS_VOLUME_DATA_BUFFER
    {
        public long VolumeSerialNumber;
        public long NumberSectors;
        public long TotalClusters;
        public long FreeClusters;
        public long TotalReserved;
        public uint BytesPerSector;
        public uint BytesPerCluster;
        public uint BytesPerFileRecordSegment;
        public uint ClustersPerFileRecordSegment;
        public long MftValidDataLength;
        public long MftStartLcn;
        public long Mft2StartLcn;
        public long MftZoneStart;
        public long MftZoneEnd;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        void* lpInBuffer,
        uint nInBufferSize,
        void* lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool ReadFile(
        SafeFileHandle hFile,
        void* lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
