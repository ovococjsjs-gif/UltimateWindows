namespace UltimateWindows.Modules.Repair.Bsod;

/// <summary>
/// Отличает модули ядра, входящие в состав Windows, от драйверов сторонних производителей
/// и подсказывает, какому устройству или программе принадлежит известный сторонний драйвер.
///
/// В малом дампе нет сведений о цифровой подписи, есть только имена файлов, поэтому различение идёт по именам.
/// Модуль, которого нет в списке Windows, считается сторонним.
/// </summary>
public static class KernelModuleClassifier
{
    private static readonly HashSet<string> WindowsComponents = new(StringComparer.OrdinalIgnoreCase)
    {
        // Ядро, HAL, загрузка и отладка
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe", "hal.dll", "halmacpi.dll",
        "kdcom.dll", "kdnet.dll", "kdstub.dll", "bootvid.dll", "pshed.dll", "ci.dll", "clfs.sys", "tm.sys",
        "mcupdate_genuineintel.dll", "mcupdate_authenticamd.dll", "werkernel.sys", "ntosext.sys",
        "cmimcext.sys", "clipsp.sys", "ksecdd.sys", "ksecpkg.sys", "cng.sys", "msrpc.sys", "pcw.sys",
        "crashdmp.sys", "hvix64.exe", "hvax64.exe", "hvloader.dll", "securekernel.exe", "skci.dll",
        "winhv.sys", "winhvr.sys", "vmbus.sys", "vmbkmcl.sys", "vmbkmclr.sys", "hvservice.sys", "hvsocket.sys",
        "vid.sys", "vpcivsp.sys", "storvsp.sys", "vmswitch.sys", "vfpext.sys", "wcifs.sys", "cldflt.sys",
        "bindflt.sys", "storqosflt.sys", "peauth.sys", "condrv.sys", "mmcss.sys", "null.sys", "beep.sys",

        // Платформа драйверов, ACPI, шины
        "wdf01000.sys", "wdfldr.sys", "wudfrd.sys", "wudfpf.sys", "acpi.sys", "acpiex.sys", "wmilib.sys",
        "pci.sys", "pdc.sys", "cea.sys", "msisadrv.sys", "vdrvroot.sys", "compositebus.sys", "umbus.sys",
        "swenum.sys", "rdpbus.sys", "mssmbios.sys", "ndisvirtualbus.sys", "kdnic.sys", "uefi.sys",
        "wmiacpi.sys", "cmbatt.sys", "battc.sys", "msgpioclx.sys", "spbcx.sys", "acpipagr.sys",
        "acpitime.sys", "acpipmi.sys", "wfplwfs.sys", "windowstrustedrt.sys", "windowstrustedrtproxy.sys",
        "intelppm.sys", "amdppm.sys", "processr.sys", "intelpep.sys", "amdpep.sys", "tpm.sys", "tbs.sys",
        "sleepstudyhelper.sys", "bam.sys", "dam.sys", "gpuenergydrv.sys", "vhf.sys", "errdev.sys",

        // Графическая подсистема
        "win32k.sys", "win32kbase.sys", "win32kfull.sys", "win32ksgd.sys", "cdd.dll", "dxgkrnl.sys",
        "dxgmms1.sys", "dxgmms2.sys", "watchdog.sys", "basicdisplay.sys", "basicrender.sys", "monitor.sys",
        "indirectkmd.sys",

        // Накопители и файловые системы
        "volmgr.sys", "volmgrx.sys", "mountmgr.sys", "partmgr.sys", "fvevol.sys", "volsnap.sys", "volume.sys",
        "rdyboost.sys", "ntfs.sys", "refs.sys", "fastfat.sys", "exfat.sys", "cdfs.sys", "udfs.sys",
        "fltmgr.sys", "fileinfo.sys", "wof.sys", "luafv.sys", "npsvctrig.sys", "npfs.sys", "msfs.sys",
        "filecrypt.sys", "storport.sys", "storahci.sys", "stornvme.sys", "spaceport.sys", "ehstorclass.sys",
        "classpnp.sys", "disk.sys", "cdrom.sys", "ataport.sys", "atapi.sys", "pciidex.sys", "intelide.sys",
        "sdbus.sys", "sdstor.sys", "usbstor.sys", "uaspstor.sys", "iorate.sys", "mup.sys", "dfsc.sys",

        // Сеть
        "ndis.sys", "netio.sys", "tcpip.sys", "tcpipreg.sys", "fwpkclnt.sys", "afd.sys", "http.sys",
        "tdx.sys", "tdi.sys", "netbt.sys", "netbios.sys", "nsiproxy.sys", "pacer.sys", "mpsdrv.sys",
        "rdbss.sys", "csc.sys", "mrxsmb.sys", "mrxsmb10.sys", "mrxsmb20.sys", "srv2.sys", "srvnet.sys",
        "bowser.sys", "lltdio.sys", "rspndr.sys", "mslldp.sys", "ndisuio.sys", "nwifi.sys", "vwififlt.sys",
        "vwifibus.sys", "vwifimp.sys", "wanarp.sys", "ndiswan.sys", "ndistapi.sys", "raspppoe.sys",
        "raspptp.sys", "rasl2tp.sys", "rassstp.sys", "agilevpn.sys", "ndproxy.sys", "ndiscap.sys",
        "wdiwifi.sys", "netadaptercx.sys", "mbbcx.sys", "wificx.sys", "nduw.sys", "ndu.sys",

        // USB, ввод, звук, Bluetooth
        "usbd.sys", "usbport.sys", "usbehci.sys", "usbuhci.sys", "usbohci.sys", "usbhub.sys", "usbhub3.sys",
        "usbxhci.sys", "ucx01000.sys", "usbccgp.sys", "winusb.sys", "usbprint.sys", "usbser.sys",
        "urscx01000.sys", "ucmcx.sys", "ucmucsicx.sys", "ucmucsiacpiclient.sys", "hidclass.sys",
        "hidparse.sys", "hidusb.sys", "hidi2c.sys", "hidspi.sys", "mshidkmdf.sys", "kbdclass.sys",
        "kbdhid.sys", "mouclass.sys", "mouhid.sys", "i8042prt.sys", "serial.sys", "serenum.sys",
        "xboxgip.sys", "xusb22.sys", "xinputhid.sys", "ks.sys", "ksthunk.sys", "portcls.sys", "drmk.sys",
        "hdaudio.sys", "hdaudbus.sys", "usbaudio.sys", "usbaudio2.sys", "bthport.sys", "bthusb.sys",
        "bthenum.sys", "bthmini.sys", "bthpan.sys", "bthmodem.sys", "rfcomm.sys", "btha2dp.sys",
        "bthhfenum.sys", "bthleenum.sys", "microsoft.bluetooth.legacy.leenumerator.sys",

        // Защитник Windows и прочие встроенные фильтры
        "wdfilter.sys", "wdnisdrv.sys", "wdboot.sys", "wddevflt.sys", "mssecflt.sys", "mssecwfp.sys",
        "appid.sys", "applockerfltr.sys", "sgrmagent.sys", "wtd.sys", "bfs.sys", "ahcache.sys"
    };

    private static readonly (string Prefix, string Description)[] KnownThirdPartyDrivers =
    [
        // Видеокарты
        ("nvlddmkm", "видеодрайвер NVIDIA"),
        ("nvhda", "аудиодрайвер NVIDIA HDMI"),
        ("nvvad", "виртуальное аудиоустройство NVIDIA"),
        ("amdkmdag", "видеодрайвер AMD Radeon"),
        ("atikmdag", "видеодрайвер AMD Radeon"),
        ("atikmpag", "видеодрайвер AMD Radeon"),
        ("amdfendr", "служебный драйвер AMD Radeon"),
        ("igdkmd", "видеодрайвер Intel Graphics"),

        // Сеть
        ("rt640x64", "сетевой драйвер Realtek Ethernet"),
        ("rt68cx21", "сетевой драйвер Realtek Ethernet"),
        ("rt25cx21", "сетевой драйвер Realtek 2.5G Ethernet"),
        ("rtwlan", "драйвер Wi-Fi адаптера Realtek"),
        ("netwtw", "драйвер Wi-Fi адаптера Intel"),
        ("netwbw", "драйвер Wi-Fi адаптера Intel"),
        ("e1d6", "сетевой драйвер Intel Ethernet"),
        ("e1r6", "сетевой драйвер Intel Ethernet"),
        ("e2f6", "сетевой драйвер Intel 2.5G Ethernet"),
        ("mtkwl", "драйвер Wi-Fi адаптера MediaTek"),
        ("qcamain", "драйвер Wi-Fi адаптера Qualcomm Atheros"),
        ("athw", "драйвер Wi-Fi адаптера Qualcomm Atheros"),
        ("bcmwl", "драйвер Wi-Fi адаптера Broadcom"),

        // Накопители и чипсет
        ("iastor", "драйвер контроллера накопителей Intel RST"),
        ("iaLPSS", "драйвер чипсета Intel Serial IO"),
        ("secnvme", "драйвер накопителя Samsung NVMe"),
        ("amdxata", "драйвер контроллера накопителей AMD"),
        ("rcraid", "драйвер AMD RAID"),
        ("asmtxhci", "драйвер USB-контроллера ASMedia"),

        // Звук
        ("rtkvhd", "аудиодрайвер Realtek"),
        ("nahimic", "драйвер звуковых эффектов Nahimic"),

        // Античиты
        ("vgk.", "античит Riot Vanguard"),
        ("bedaisy", "античит BattlEye"),
        ("easyanticheat", "античит Easy Anti-Cheat"),
        ("faceit", "античит FACEIT"),
        ("xhunter", "античит XIGNCODE3"),
        ("mhyprot", "античит miHoYo"),

        // Антивирусы
        ("asw", "драйвер антивируса Avast"),
        ("avg", "драйвер антивируса AVG"),
        ("klif", "драйвер антивируса Kaspersky"),
        ("klhk", "драйвер антивируса Kaspersky"),
        ("klflt", "драйвер антивируса Kaspersky"),
        ("kneps", "драйвер антивируса Kaspersky"),
        ("eamonm", "драйвер антивируса ESET"),
        ("ehdrv", "драйвер антивируса ESET"),
        ("epfw", "драйвер антивируса ESET"),
        ("dwprot", "драйвер антивируса Dr.Web"),
        ("mbam", "драйвер Malwarebytes"),
        ("mfe", "драйвер антивируса McAfee"),
        ("trufos", "драйвер антивируса Bitdefender"),
        ("bdfwfpf", "драйвер антивируса Bitdefender"),
        ("symefasi", "драйвер антивируса Norton"),
        ("srtsp", "драйвер антивируса Norton"),

        // Виртуализация, VPN, перехват сети
        ("vboxdrv", "драйвер VirtualBox"),
        ("vboxnet", "сетевой драйвер VirtualBox"),
        ("vmx86", "драйвер VMware"),
        ("vmnet", "сетевой драйвер VMware"),
        ("tap0901", "виртуальный сетевой адаптер TAP (VPN)"),
        ("wintun", "виртуальный сетевой адаптер Wintun (VPN)"),
        ("wireguard", "драйвер WireGuard (VPN)"),
        ("npcap", "драйвер перехвата сети Npcap"),
        ("npf.", "драйвер перехвата сети WinPcap"),

        // Утилиты мониторинга и разгона, подсветка
        ("rtcore64", "драйвер утилиты MSI Afterburner"),
        ("winring0", "устаревший уязвимый драйвер мониторинга WinRing0"),
        ("inpoutx64", "устаревший уязвимый драйвер прямого доступа к портам"),
        ("cpuz", "драйвер утилиты CPU-Z"),
        ("hwinfo", "драйвер утилиты HWiNFO"),
        ("gdrv", "драйвер утилит Gigabyte"),
        ("asio", "драйвер утилит ASUS"),
        ("ene.", "драйвер управления подсветкой (ENE)"),
        ("eneio", "драйвер управления подсветкой (ENE)"),
        ("glckio", "драйвер управления подсветкой ASUS Aura")
    ];

    /// <summary>
    /// Возвращает true, если модуль входит в состав Windows.
    /// </summary>
    public static bool IsWindowsComponent(string moduleName)
    {
        if (string.IsNullOrWhiteSpace(moduleName))
        {
            return false;
        }

        var name = moduleName.Trim();
        if (WindowsComponents.Contains(name))
        {
            return true;
        }

        // Копии драйверов накопителя, которыми Windows пишет сам дамп (dump_storahci.sys и подобные)
        return name.StartsWith("dump_", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Короткое описание известного стороннего драйвера или null, если драйвер не опознан.
    /// </summary>
    public static string? DescribeKnownDriver(string moduleName)
    {
        if (string.IsNullOrWhiteSpace(moduleName))
        {
            return null;
        }

        var name = moduleName.Trim();
        foreach (var (prefix, description) in KnownThirdPartyDrivers)
        {
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return description;
            }
        }

        return null;
    }
}
