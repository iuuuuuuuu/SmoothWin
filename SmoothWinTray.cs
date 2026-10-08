// SmoothWinTray - 常驻后台的内存与卡顿缓解工具
// 目标: .NET Framework 4.8 (Windows 10 1903+ / Windows 11 自带运行时)
// 编译: csc /target:winexe /optimize+ /codepage:65001
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SmoothWinTray
{
    // ==================== 本机 API ====================
    internal static class Native
    {
        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern bool EmptyWorkingSet(IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr h);

        // 每进程磁盘读写量：要回答「谁在拼命读盘」只能靠它，
        // .NET 的 Process 类不暴露 IO 计数器（ProcessIoCounters 不是公开 API）。
        [StructLayout(LayoutKind.Sequential)]
        internal struct IO_COUNTERS
        {
            public ulong ReadOperationCount, WriteOperationCount, ReadTransferCount, WriteTransferCount,
                         OtherOperationCount, OtherTransferCount;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);

        // 累计 CPU 时间（内核 + 用户），单位 100 纳秒。
        // 不能用 .NET 的 Process.TotalProcessorTime：本机 421 个进程要 7 秒，
        // 而采样间隔只有 5 秒 —— 程序自己就成了最大的卡顿来源。
        // 直接调这个 API，同样的数据只要 30~60 毫秒。
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetProcessTimes(IntPtr h, out long create, out long exit, out long kernel, out long user);

        internal const uint PROCESS_QUERY_INFORMATION = 0x0400;

        [DllImport("ntdll.dll")]
        internal static extern int NtSetSystemInformation(int infoClass, IntPtr info, int length);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LookupPrivilegeValue(string system, string name, out long luid);

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attr; }

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr tok, bool disable, ref TOKEN_PRIVILEGES np, int len, IntPtr prev, IntPtr ret);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        internal static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        internal const int EM_GETFIRSTVISIBLELINE = 0x00CE;
        internal const int EM_LINESCROLL = 0x00B6;

        // 多行文本框的滚动位置只能问「第一行可见行号」。
        // 实测 EM_GET/SETSCROLLPOS 在 WinForms TextBox 上恒返回 (0,0)，不可用；
        // EM_GETFIRSTVISIBLELINE + EM_LINESCROLL 是可靠的一对。
        internal static int GetFirstVisibleLine(IntPtr h)
        {
            try { return (int)SendMessage(h, EM_GETFIRSTVISIBLELINE, IntPtr.Zero, IntPtr.Zero); }
            catch { return 0; }
        }
        internal static void ScrollLines(IntPtr h, int lines)
        {
            if (lines == 0) return;
            try { SendMessage(h, EM_LINESCROLL, IntPtr.Zero, (IntPtr)lines); } catch { }
        }

        // ---- 键鼠空闲时长：判断「用户到底在不在用这台电脑」 ----
        // CPU / 磁盘型压力只有在人没在用电脑时才值得提醒。人正敲着键盘，
        // CPU 高恰恰是因为他在编译、跑任务、看视频 —— 那正是他要用的程序，
        // 提醒他「有个程序占着 CPU」等于让他把自己的活儿关掉。
        [StructLayout(LayoutKind.Sequential)]
        internal struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        // 返回距上次键鼠输入经过的分钟数；取不到时返回 -1（调用方按「不确定」处理）。
        // 用 dwTime（系统启动以来的毫秒数）与 Environment.TickCount 相减，
        // 两者同源，不受系统时间被改动的影响。
        internal static double IdleMinutes()
        {
            try
            {
                LASTINPUTINFO li = new LASTINPUTINFO();
                li.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                if (!GetLastInputInfo(ref li)) return -1;
                uint now = (uint)Environment.TickCount;
                // TickCount 约 49.7 天回绕一次，用无符号减法天然处理回绕
                uint idle = now - li.dwTime;
                if (idle > 0x7FFFFFFF) return -1;   // 明显异常（时钟回绕/取到脏值）
                return idle / 60000.0;
            }
            catch { return -1; }
        }

        // 枚举顶层窗口，用于判断某个进程「是不是有窗口正开着」。
        // 只取「可见 + 未最小化」的窗口：最小化的窗口按「没在用」处理
        // （很多程序最小化后会自己挂起，不需要我们去推它的工作集）。
        internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        internal static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);

        [DllImport("user32.dll")]
        internal static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        internal static extern bool IsIconic(IntPtr hWnd);

        // 取所有「有可见且未最小化窗口」的进程 ID
        internal static HashSet<int> VisibleWindowPids()
        {
            HashSet<int> set = new HashSet<int>();
            try
            {
                EnumWindows(delegate (IntPtr h, IntPtr l)
                {
                    try
                    {
                        if (!IsWindowVisible(h)) return true;
                        if (IsIconic(h)) return true;      // 最小化 = 没在用
                        int pid;
                        if (GetWindowThreadProcessId(h, out pid) != 0 && pid > 0) set.Add(pid);
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);
            }
            catch { }
            return set;
        }

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();

        // 抓窗口内容（PrintWindow + flags=2 = PW_RENDERFULLCONTENT），不依赖屏幕是否解锁
        [DllImport("user32.dll")]
        internal static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);

        [DllImport("user32.dll")]
        internal static extern bool GetWindowRect(IntPtr hwnd, out Rectangle r);

        [DllImport("user32.dll")]
        internal static extern int GetWindowThreadProcessId(IntPtr hWnd, out int pid);

        // 每个进程「有没有窗口、哪个是主窗口」。一次 EnumWindows 全扫完，
        // 不能按进程去扫（421 个进程 × 一次全枚举 = 界面直接卡死）。
        internal static Dictionary<int, IntPtr> TopWindows()
        {
            Dictionary<int, IntPtr> r = new Dictionary<int, IntPtr>();
            try
            {
                EnumWindows(delegate (IntPtr h, IntPtr l)
                {
                    try
                    {
                        if (!IsWindowVisible(h)) return true;
                        int p;
                        if (GetWindowThreadProcessId(h, out p) == 0 || p <= 0) return true;
                        if (!r.ContainsKey(p)) r[p] = h;
                        // 已经记下的那个是最小化窗口、现在这个是正常显示的 → 换成这个
                        else if (IsIconic(r[p]) && !IsIconic(h)) r[p] = h;
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);
            }
            catch { }
            return r;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder buf, ref int size);

        // 进程的完整 exe 路径。用已有的句柄取，不再多开一次进程句柄。
        internal static string ProcessPathOf(IntPtr h)
        {
            try
            {
                if (h == IntPtr.Zero) return "";
                StringBuilder sb = new StringBuilder(1024);
                int n = sb.Capacity;
                if (!QueryFullProcessImageNameW(h, 0, sb, ref n)) return "";
                return sb.ToString(0, n);
            }
            catch { return ""; }
        }

        // 关窗口（温和）与切到前台。给用户的选项里「关窗口」是最轻的一个：
        // 程序该保存的自己会弹框，比直接结束进程安全得多。
        [DllImport("user32.dll", SetLastError = true)]
        internal static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);

        [DllImport("user32.dll")]
        internal static extern bool SetForegroundWindow(IntPtr hWnd);

        internal const uint WM_CLOSE = 0x0010;

        // 「用户是不是点过退出」用一个内核事件对象来记，而不是标志文件：
        //   · 事件属于内核对象，进程/机器重启后自动消失，不会留下一块需要清理的状态；
        //   · 计划任务的定时触发器同样是内核对象，用户点退出后会被关掉、不再触发，
        //     所以「重启之后自启能力自动恢复」是天然成立的，不用额外写恢复逻辑。
        internal const uint ERROR_ALREADY_EXISTS = 183;

        // 系统启动以来的毫秒数（64 位）。.NET Framework 4.x 的 Environment.TickCount 是
        // int（约 24.9 天翻转），这里用原生 64 位版本算「本次开机时刻」。
        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        internal static ulong UptimeMs()
        {
            try { return GetTickCount64(); }
            catch { return 0; }
        }
        internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateEventW(IntPtr attr, bool manualReset, bool initialState, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint ms);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ResetEvent(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetEvent(IntPtr handle);

        // 取「父进程是谁」只能靠 Toolhelp32（.NET 的 Process 类不暴露父进程）。
        // 用途：区分「计划任务把我拉起来」和「用户自己双击图标」。
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        internal const uint TH32CS_SNAPPROCESS = 0x00000002;

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32 pe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32 pe);

        [StructLayout(LayoutKind.Sequential)]
        internal class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX buf);

        internal const uint PROCESS_SET_QUOTA = 0x0100;
        internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        internal const int SystemMemoryListInformation = 80;
        // 只用「刷新已修改页面列表」这一种。同一接口还支持 MemoryEmptyWorkingSets(2)
        // 与 MemoryPurgeStandbyList(4)，但两者都是负优化：前者一次清空所有进程的工作集，
        // 后者清空待机缓存，结果是随后每个程序都要重新读盘、硬缺页暴涨、界面立刻变卡。
        // 这正是很多「内存优化软件」越优化越卡的原因，本程序不做这两件事。
        internal const int MemoryFlushModifiedList = 3;

        internal static bool EnablePrivilege(string name)
        {
            IntPtr tok;
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out tok)) return false;
            try
            {
                long luid;
                if (!LookupPrivilegeValue(null, name, out luid)) return false;
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.Count = 1; tp.Luid = luid; tp.Attr = 0x00000002;
                return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally { CloseHandle(tok); }
        }

        internal static int MemoryList(int command)
        {
            IntPtr p = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(p, command);
                return NtSetSystemInformation(SystemMemoryListInformation, p, 4);
            }
            finally { Marshal.FreeHGlobal(p); }
        }

        // ---- 配置管理器（cfgmgr32）：读设备的问题代码，就是设备管理器里那个黄色感叹号 ----
        // 比走 WMI 快得多，也不依赖 WMI 服务是否正常。
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern int CM_Get_Device_ID_List_Size(out int len, string filter, int flags);
        // 注意：这里必须用 char[] 而不是 StringBuilder。
        // StringBuilder 会被 marshal 成 LPWStr，返回时 .NET 按第一个 '\0' 截断，
        // 结果只能拿到 1 个设备 ID（实测踩过：明明有 12 个异常设备却扫出 0 个）。
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern int CM_Get_Device_ID_List(string filter, [Out] char[] list, int len, int flags);
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern int CM_Locate_DevNode(out int devInst, string deviceID, int flags);
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern int CM_Get_DevNode_Status(out int status, out int problem, int devInst, int flags);
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern int CM_Get_DevNode_Registry_Property(int devInst, int property, out int regType,
            StringBuilder buffer, ref int length, int flags);

        internal const int CM_GETIDLIST_FILTER_PRESENT = 0x00000100;
        internal const int SPDRP_DEVICEDESC = 0x00000000;
        internal const int SPDRP_CLASS = 0x00000007;
        internal const int SPDRP_MFG = 0x0000000B;
        internal const int SPDRP_FRIENDLYNAME = 0x0000000C;
    }

    // ==================== 配置 ====================
    internal class Config
    {
        public int CommitThresholdPct = 80;
        public int CompressionThresholdMB = 1500;
        // ★ 300 秒太短：实测每 5 分钟整理一次会把「刚被推到 pagefile 的页」反复
        //   再推一遍，硬缺页根本没机会降下来，反而形成自激环路。默认改成 30 分钟。
        public int CooldownSeconds = 1800;
        public int MinTrimMB = 150;
        public int SampleSeconds = 5;
        public int HistoryMinutes = 5;
        public int HeartbeatSeconds = 60;        // 心跳写盘间隔（秒）；用于事后判断进程何时消失
        public int PeriodicTrimMinutes = 0;
        public bool AutoTrim = true;
        public bool WarnOnTdr = true;
        // ---- 通用化 / 自适应（不依赖具体机器）----
        public bool AutoTune = true;             // 按物理内存容量自动调阈值
        public int LeakSampleMinutes = 5;        // 进程增长采样间隔（分钟，0=关闭）
        // ★ 200 太低：node / firefox / qemu 正常跑起来就是几百 MB/小时的增长，
        //   于是每次启动都立刻弹一次「发现越用越大的程序」，用户看到的就是「一直提示我」。
        //   真正值得干预的泄漏是长期稳定的高速增长，阈值放到 500 并配合连续确认。
        public int LeakWarnMBPerHour = 500;      // 工作集增长超过此速率 -> 疑似泄漏
        public bool WarnOnLeak = true;           // 疑似泄漏时气泡提醒
        public bool WarnOnStress = true;         // 换页压力/DPC 偏高时提醒
        // ★ 2000 太低：本机 history.csv 实测硬缺页 p50 只有 9.6、avg 1979、max 51166，
        //   2000 正好卡在平均值上，任何一次瞬时尖峰都会误报成「内存吃紧」。
        //   真正持续的换页压力是几万次/秒级别，默认改成 20000。
        public int StressHardFaults = 20000;     // 硬缺页(次/秒)超过此值视为内存吃紧
        public int StressDpcPct = 25;            // DPC 占用超过此百分比视为驱动层卡顿
        // ★ 90% 太容易碰到：本机常驻 qemu/node/rustc 编译，CPU 长期在 90%+，
        //   提醒就变成了「一直提示我」。真正需要干预的是「快跑满了还停不下来」。
        public int StressCpuPct = 95;            // CPU 总占用超过此百分比视为 CPU 型卡顿
        public int StressDiskPct = 90;           // 磁盘繁忙超过此百分比（且队列 >= 2）视为磁盘型卡顿
        public int StressConfirmSamples = 12;    // 连续多少次采样超标才算「持续」（避免瞬时尖峰误报）
        // ---- 「别再一直提示我」相关（用户要求：node/firefox 是我在用的，别老弹）----
        // 同类提醒的最短间隔。没有这个节流时，压力一解除 stressNotified 立刻复位，
        // 30 秒后又能弹一次 —— 实测日志里 22:31:25 和 22:32:10 各弹了一次。
        public int StressWarnCooldownMinutes = 30;
        // CPU / 磁盘型压力「只在用户确实没在用电脑时才提醒」。
        // 判据是键鼠空闲时长：人一直在敲键盘，说明 CPU 高是因为他在干活（编译、跑任务），
        // 这时候提醒「有个程序占着 CPU」纯属添乱 —— 那正是他要用的程序。
        public bool StressIdleOnly = true;
        public int StressIdleMinutes = 10;       // 键鼠空闲超过这么多分钟才算「没在用」
        // ★ 用户明确要求（原话大意）：node / firefox 这些「我常用、正在用」的程序别一直提示我。
        //   CPU / 磁盘型压力如果最耗资源的是「用户自己的程序」，说明那是他在干活，不是故障 ——
        //   只写日志，不弹气泡。只有系统进程长期占满才值得提醒。
        public bool StressIgnoreUserPrograms = true;
        public int LeakWarnConfirm = 3;          // 增长追踪连续几次采样都超标才提醒
        public int StressFixAttempts = 2;        // 自动深度整理几次仍无效才打扰用户
        public bool AutoFixStress = true;        // 检测到持续换页压力时先自动处理
        public bool SilentAutoTrim = true;       // 自动整理不再弹气泡（只写日志）
        public bool WarnOnReboot = true;         // 有「重启后才生效」的改动挂太久时提醒
        public int RebootNoticeDays = 3;         // 连续运行超过这么多天且有待重启项 -> 提醒一次
        // ---- 「不打扰正在用的程序」相关（用户要求：firefox / node 这些我还要用，别叫我关）----
        public bool TrimIdleOnly = true;         // 只整理「当前没在干活」的进程；正在用的程序绝不碰
        public int TrimCooldownSeconds = 900;    // 同一个进程两次整理之间至少间隔多少秒
        public bool AggressiveFlushModified = false; // 深度整理时强制把已修改页面写盘（会制造读盘高峰，默认关）
        // ★ 增长提醒的忽略名单：逗号/分号分隔的进程名（不区分大小写）。
        //   用户的开发工具（node、java、docker…）本来就该越跑越大，提醒他「node 一直在变大」
        //   等于什么都没说 —— 用户原话（m02756 大意）：「node 是我开发工具，提示我这个也没用」。
        //   同一个程序提醒满 LeakMuteAfter 次后会自动写进这里，以后彻底静音。
        public string LeakIgnoreNames = "";
        public int LeakMuteAfter = 3;            // 同一个程序提醒几次后自动静音（0=从不自动静音）

        public bool IsLeakIgnored(string name)
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(LeakIgnoreNames)) return false;
            string[] parts = LeakIgnoreNames.Split(new char[] { ',', ';', ' ', '，', '；', '、' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
                if (string.Equals(parts[i].Trim(), name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public void AddLeakIgnore(string name)
        {
            if (string.IsNullOrEmpty(name) || IsLeakIgnored(name)) return;
            LeakIgnoreNames = string.IsNullOrEmpty(LeakIgnoreNames) ? name.Trim() : LeakIgnoreNames + "," + name.Trim();
        }

        // 配置文件里显式写过的项（写了就不再被自适应覆盖）。
        // 注意：这三项只在「手动模式」下才会被置位；自动模式下 Save 写的是 auto，
        // 于是换机器 / 加内存后阈值会重新按容量算，不会被一次「保存」永久固化。
        public bool UserSetCommit, UserSetComp, UserSetMinTrim;
        // 上次自适应时看到的物理内存（MB）。给「与容量相关」的运行时判据用
        // （例如非分页池告警线），跟 AutoTune 是否开启无关，总是记录。
        public long TotalPhysMB;

        private static string _dir;

        // 记录数据目录三级回退的判定过程，供日志排查（由 Main 在解析后写出）。
        public static string DirNotes = "";

        // 自动化测试用：把数据目录指到别处（配置、日志、历史都写过去），
        // 这样实测「手动退出后不再复活」时不会碰到用户的真实配置。
        public static void OverrideDir(string d)
        {
            try
            {
                if (string.IsNullOrEmpty(d)) return;
                if (!Directory.Exists(d)) Directory.CreateDirectory(d);
                _dir = d;
                TestMode = true;
                DirNotes = "命令行 --testdir 指定（测试用）";
            }
            catch { }
        }

        // 自动化实测：启动后多少秒自动点一次「退出」（0 = 不自动退出）
        public static int TestExitAfterSec;

        // 自动化实测标志：只有 --testdir 才会置位。
        // 作用：退出的确认框自动回答「是」——没人坐在屏幕前点按钮，
        // 弹一个模态框会把实测卡死；而实测要验证的正是「确认之后」的那条路径。
        public static bool TestMode;

        // 优先 %LOCALAPPDATA%\SmoothWin；若不可写（受限令牌/权限异常），依次回退到
        // exe 同级目录、%TEMP%，保证程序在任何环境下都能留下日志与配置。
        public static string Dir
        {
            get
            {
                if (_dir != null) return _dir;
                string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrEmpty(la)) la = Environment.GetEnvironmentVariable("LOCALAPPDATA");
                string[] candidates = new string[]
                {
                    string.IsNullOrEmpty(la) ? "" : Path.Combine(la, "SmoothWin"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SmoothWinData"),
                    Path.Combine(Path.GetTempPath(), "SmoothWin")
                };
                foreach (string d in candidates)
                {
                    try
                    {
                        if (string.IsNullOrEmpty(d)) throw new Exception("路径为空（无法解析用户目录）");
                        if (!Directory.Exists(d)) Directory.CreateDirectory(d);
                        string probe = Path.Combine(d, ".wtest");
                        File.AppendAllText(probe, "1");
                        File.Delete(probe);
                        _dir = d;
                        DirNotes += "[" + d + " = 可写] ";
                        return _dir;
                    }
                    catch (Exception ex)
                    {
                        DirNotes += "[" + d + " 失败: " + ex.GetType().Name + " - " + ex.Message + "] ";
                    }
                }
                _dir = candidates[0];
                DirNotes += "全部不可写，强制使用 " + _dir;
                return _dir;
            }
        }
        // 按物理内存容量给出通用默认阈值：小内存机器更敏感，大内存机器更宽松。
        public static int TunedCommitPct(long totalPhysMB)
        {
            if (totalPhysMB <= 4096) return 72;
            if (totalPhysMB <= 8192) return 78;
            if (totalPhysMB <= 16384) return 82;
            if (totalPhysMB <= 32768) return 85;
            return 88;
        }
        public static int TunedCompressionMB(long totalPhysMB)
        {
            long v = (long)(totalPhysMB * 0.05);   // 物理内存的 5%
            if (v < 512) v = 512;
            if (v > 4096) v = 4096;
            return (int)v;
        }

        // 只整理「工作集大于 X MB」的进程：4GB 机器上 150MB 已经是大进程，
        // 64GB 机器上 150MB 遍地都是，整理它们纯属浪费 CPU。按物理内存的 0.25% 推算，
        // 并夹在 [64, 512] 之间。
        public static int TunedMinTrimMB(long totalPhysMB)
        {
            long v = (long)(totalPhysMB * 0.0025);
            if (v < 64) v = 64;
            if (v > 512) v = 512;
            return (int)v;
        }

        // 非分页池告警线。以前这里是写死的 3072MB：4GB 机器一辈子碰不到这条线，
        // 64GB 机器上驱动泄漏到 3GB 其实还早得很。内核池随物理内存增长是次线性的，
        // 所以用「固定底数 + 容量百分比」：512 + 内存×3%，夹在 [512, 4096]。
        //   4GB→635  8GB→758  16GB→1003  32GB→1494  64GB→2454
        public long TunedPoolNonPagedMB()
        {
            long t = TotalPhysMB > 0 ? TotalPhysMB : 8192;
            long v = 512 + (long)(t * 0.03);
            if (v < 512) v = 512;
            if (v > 4096) v = 4096;
            return v;
        }

        public static string BaselinePath { get { return Path.Combine(Dir, "proc-baseline.csv"); } }

        // 自适应：只有当配置文件里没有显式写过该项时才套用，避免覆盖用户的选择。
        public void ApplyAutoTune(long totalPhysMB)
        {
            if (totalPhysMB > 0) TotalPhysMB = totalPhysMB;
            if (totalPhysMB <= 0) return;

            // 老版本的 ini 里存的是「当时算出来的数字」，跟「用户手填的数字」没法区分，
            // 于是升级到本版本后它们会被当成手动值，永远不再随容量变化 —— 这正是
            // 「一台机器上的阈值被带到另一台机器」的老毛病。这里做一次性迁移：
            // 如果这个数字正好等于本机按容量算出来的值，就认定它当初是自动写的，放回自动。
            // 用户若真的手填了同一个数，行为也完全一样（值不变），所以不存在误伤。
            if (AutoTune)
            {
                if (UserSetCommit && CommitThresholdPct == TunedCommitPct(totalPhysMB)) UserSetCommit = false;
                if (UserSetComp && CompressionThresholdMB == TunedCompressionMB(totalPhysMB)) UserSetComp = false;
                // MinTrimMB 还要多认一种情况：旧版本里这项的出厂默认就是 150，
                // 从没被人改过的老 ini 里必然是这个数 —— 那不是用户的选择，是旧默认值。
                if (UserSetMinTrim && (MinTrimMB == 150 || MinTrimMB == TunedMinTrimMB(totalPhysMB))) UserSetMinTrim = false;
            }
            if (!AutoTune) return;
            if (!UserSetCommit) CommitThresholdPct = TunedCommitPct(totalPhysMB);
            if (!UserSetComp) CompressionThresholdMB = TunedCompressionMB(totalPhysMB);
            if (!UserSetMinTrim) MinTrimMB = TunedMinTrimMB(totalPhysMB);
        }

        public static string ConfigPath { get { return Path.Combine(Dir, "tray-config.ini"); } }
        public static string HistoryPath { get { return Path.Combine(Dir, "history.csv"); } }
        public static string LogPath { get { return Path.Combine(Dir, "SmoothWinTray.log"); } }

        public static Config Load()
        {
            Config c = new Config();
            try
            {
                if (File.Exists(ConfigPath))
                {
                    foreach (string raw in File.ReadAllLines(ConfigPath))
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;
                        int i = line.IndexOf('=');
                        if (i <= 0) continue;
                        string k = line.Substring(0, i).Trim();
                        string v = line.Substring(i + 1).Trim();
                        int n; bool b;
                        switch (k)
                        {
                            // 值为 auto = 「按本机物理内存自动算」：不置 UserSet 标志，
                            // 于是每次启动都按当前内存重算。这样即使用户点过「保存」，
                            // 换一台机器（或加内存）也不会沿用旧机器的固定阈值。
                            case "CommitThresholdPct":
                                if (v.Equals("auto", StringComparison.OrdinalIgnoreCase)) c.UserSetCommit = false;
                                else if (int.TryParse(v, out n)) { c.CommitThresholdPct = n; c.UserSetCommit = true; }
                                break;
                            case "CompressionThresholdMB":
                                if (v.Equals("auto", StringComparison.OrdinalIgnoreCase)) c.UserSetComp = false;
                                else if (int.TryParse(v, out n)) { c.CompressionThresholdMB = n; c.UserSetComp = true; }
                                break;
                            case "CooldownSeconds": if (int.TryParse(v, out n)) c.CooldownSeconds = n; break;
                            case "MinTrimMB":
                                if (v.Equals("auto", StringComparison.OrdinalIgnoreCase)) c.UserSetMinTrim = false;
                                else if (int.TryParse(v, out n)) { c.MinTrimMB = n; c.UserSetMinTrim = true; }
                                break;
                            case "SampleSeconds": if (int.TryParse(v, out n)) c.SampleSeconds = n; break;
                            case "HistoryMinutes": if (int.TryParse(v, out n)) c.HistoryMinutes = n; break;
                            case "HeartbeatSeconds": if (int.TryParse(v, out n)) c.HeartbeatSeconds = n; break;
                            case "PeriodicTrimMinutes": if (int.TryParse(v, out n)) c.PeriodicTrimMinutes = n; break;
                            case "AutoTrim": if (bool.TryParse(v, out b)) c.AutoTrim = b; break;
                            case "WarnOnTdr": if (bool.TryParse(v, out b)) c.WarnOnTdr = b; break;
                            case "AutoTune": if (bool.TryParse(v, out b)) c.AutoTune = b; break;
                            case "LeakSampleMinutes": if (int.TryParse(v, out n)) c.LeakSampleMinutes = n; break;
                            case "LeakWarnMBPerHour": if (int.TryParse(v, out n)) c.LeakWarnMBPerHour = n; break;
                            case "WarnOnLeak": if (bool.TryParse(v, out b)) c.WarnOnLeak = b; break;
                            case "WarnOnStress": if (bool.TryParse(v, out b)) c.WarnOnStress = b; break;
                            case "StressHardFaults": if (int.TryParse(v, out n)) c.StressHardFaults = n; break;
                            case "StressDpcPct": if (int.TryParse(v, out n)) c.StressDpcPct = n; break;
                            case "StressCpuPct": if (int.TryParse(v, out n)) c.StressCpuPct = n; break;
                            case "StressDiskPct": if (int.TryParse(v, out n)) c.StressDiskPct = n; break;
                            case "StressConfirmSamples": if (int.TryParse(v, out n)) c.StressConfirmSamples = n; break;
                            case "StressWarnCooldownMinutes": if (int.TryParse(v, out n)) c.StressWarnCooldownMinutes = n; break;
                            case "StressIdleOnly": if (bool.TryParse(v, out b)) c.StressIdleOnly = b; break;
                            case "StressIdleMinutes": if (int.TryParse(v, out n)) c.StressIdleMinutes = n; break;
                            case "StressIgnoreUserPrograms": if (bool.TryParse(v, out b)) c.StressIgnoreUserPrograms = b; break;
                            case "LeakWarnConfirm": if (int.TryParse(v, out n)) c.LeakWarnConfirm = n; break;
                            case "StressFixAttempts": if (int.TryParse(v, out n)) c.StressFixAttempts = n; break;
                            case "AutoFixStress": if (bool.TryParse(v, out b)) c.AutoFixStress = b; break;
                            case "SilentAutoTrim": if (bool.TryParse(v, out b)) c.SilentAutoTrim = b; break;
                            case "WarnOnReboot": if (bool.TryParse(v, out b)) c.WarnOnReboot = b; break;
                            case "RebootNoticeDays": if (int.TryParse(v, out n)) c.RebootNoticeDays = n; break;
                            case "TrimIdleOnly": if (bool.TryParse(v, out b)) c.TrimIdleOnly = b; break;
                            case "TrimCooldownSeconds": if (int.TryParse(v, out n)) c.TrimCooldownSeconds = n; break;
                            case "AggressiveFlushModified": if (bool.TryParse(v, out b)) c.AggressiveFlushModified = b; break;
                            case "LeakIgnoreNames": c.LeakIgnoreNames = v; break;
                            case "LeakMuteAfter": if (int.TryParse(v, out n)) c.LeakMuteAfter = n; break;
                        }
                    }
                }
            }
            catch { }
            return c;
        }

        public void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("# SmoothWinTray 配置（改完重启程序生效）");
                // 自动模式写 auto（而不是当前算出来的数字）：否则一次「保存」就把本机
                // 的阈值永久固化，换机器再也不会自适应 —— 这是通用性最关键的一步。
                sb.AppendLine("CommitThresholdPct=" + (AutoTune && !UserSetCommit ? "auto" : CommitThresholdPct.ToString(CultureInfo.InvariantCulture)));
                sb.AppendLine("CompressionThresholdMB=" + (AutoTune && !UserSetComp ? "auto" : CompressionThresholdMB.ToString(CultureInfo.InvariantCulture)));
                sb.AppendLine("CooldownSeconds=" + CooldownSeconds);
                sb.AppendLine("MinTrimMB=" + (AutoTune && !UserSetMinTrim ? "auto" : MinTrimMB.ToString(CultureInfo.InvariantCulture)));
                sb.AppendLine("SampleSeconds=" + SampleSeconds);
                sb.AppendLine("HistoryMinutes=" + HistoryMinutes);
                sb.AppendLine("HeartbeatSeconds=" + HeartbeatSeconds);
                sb.AppendLine("PeriodicTrimMinutes=" + PeriodicTrimMinutes);
                sb.AppendLine("AutoTrim=" + AutoTrim);
                sb.AppendLine("WarnOnTdr=" + WarnOnTdr);
                sb.AppendLine("AutoTune=" + AutoTune);
                sb.AppendLine("LeakSampleMinutes=" + LeakSampleMinutes);
                sb.AppendLine("LeakWarnMBPerHour=" + LeakWarnMBPerHour);
                sb.AppendLine("WarnOnLeak=" + WarnOnLeak);
                sb.AppendLine("WarnOnStress=" + WarnOnStress);
                sb.AppendLine("StressHardFaults=" + StressHardFaults);
                sb.AppendLine("StressDpcPct=" + StressDpcPct);
                sb.AppendLine("StressCpuPct=" + StressCpuPct);
                sb.AppendLine("StressDiskPct=" + StressDiskPct);
                sb.AppendLine("StressConfirmSamples=" + StressConfirmSamples);
                sb.AppendLine("StressWarnCooldownMinutes=" + StressWarnCooldownMinutes);
                sb.AppendLine("StressIdleOnly=" + StressIdleOnly);
                sb.AppendLine("StressIdleMinutes=" + StressIdleMinutes);
                sb.AppendLine("StressIgnoreUserPrograms=" + StressIgnoreUserPrograms);
                sb.AppendLine("LeakWarnConfirm=" + LeakWarnConfirm);
                sb.AppendLine("StressFixAttempts=" + StressFixAttempts);
                sb.AppendLine("AutoFixStress=" + AutoFixStress);
                sb.AppendLine("SilentAutoTrim=" + SilentAutoTrim);
                sb.AppendLine("WarnOnReboot=" + WarnOnReboot);
                sb.AppendLine("RebootNoticeDays=" + RebootNoticeDays);
                sb.AppendLine("TrimIdleOnly=" + TrimIdleOnly);
                sb.AppendLine("TrimCooldownSeconds=" + TrimCooldownSeconds);
                sb.AppendLine("AggressiveFlushModified=" + AggressiveFlushModified);
                sb.AppendLine("LeakIgnoreNames=" + LeakIgnoreNames);
                sb.AppendLine("LeakMuteAfter=" + LeakMuteAfter);
                File.WriteAllText(ConfigPath, sb.ToString(), new UTF8Encoding(true));
            }
            catch { }
        }
    }

    // ==================== 日志 ====================
    internal static class Log
    {
        private static readonly object Gate = new object();
        public static void Write(string msg)
        {
            try
            {
                lock (Gate)
                {
                    string p = Config.LogPath;
                    if (File.Exists(p) && new FileInfo(p).Length > 1024 * 1024)
                    {
                        string bak = p + ".1";
                        if (File.Exists(bak)) File.Delete(bak);
                        File.Move(p, bak);
                    }
                    File.AppendAllText(p, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine, new UTF8Encoding(true));
                }
            }
            catch { }
        }

        // 心跳单独一个文件，不参与 1MB 轮转：心跳频率高，混在主日志里会把
        // 正常记录挤进 .1 备份，排查时反而看不到。心跳的唯一用途是事后区分
        // 「进程被杀掉了」和「进程还活着但卡住了」——静默消失时这是唯一证据。
        public static void Heartbeat(string msg)
        {
            try
            {
                string p = Path.Combine(Config.Dir, "heartbeat.log");
                if (File.Exists(p) && new FileInfo(p).Length > 512 * 1024) File.Delete(p);
                File.AppendAllText(p, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine, new UTF8Encoding(true));
            }
            catch { }
        }
    }

    // ==================== 内存采样 ====================
    // 单个进程的 CPU 占用（按全部核心折算的百分比）
    internal class CpuProc
    {
        public string Name = "";
        public double Pct;
        // 只有 Sample.Busy 里的条目会填 Id：那份清单是按进程 ID 计的，
        // 因为「node 开了 34 个，其中 3 个在跑」必须能区分开。
        public int Id;
    }

    internal class Sample
    {
        private static readonly DateTime Boot = DateTime.Now.AddMilliseconds(-Environment.TickCount);
        public DateTime Time;
        public double UptimeHours;
        public long TotalMB, AvailMB, CommitMB, CommitLimitMB, CommitPct;
        public long PoolNonPagedMB, PoolPagedMB, StandbyMB, ModifiedMB, CompressionMB;
        public int Procs, Threads, Handles;
        // 换页压力与内核时间占用（-1 = 该计数器在本机不可用，不影响其它功能）
        public double PageFaultsPerSec = -1, HardFaultsPerSec = -1, DpcPct = -1, InterruptPct = -1;
        // CPU 与磁盘（-1 = 该计数器在本机不可用）。卡顿不一定是内存问题，也可能是
        // 某个程序把 CPU 跑满，或者磁盘 100% 忙——先量出来才能对症。
        public double CpuPct = -1, DiskBusyPct = -1, DiskQueue = -1, DiskMBps = -1;
        // 进程级 CPU 占用（前 N 名），用于回答「到底是哪个程序在吃 CPU」
        public List<CpuProc> TopCpu = new List<CpuProc>();
        public List<CpuProc> TopDisk = new List<CpuProc>();   // Pct 字段复用为 MB/s
        // 本窗口内「在干活」的进程：Pct = CPU 毫秒数 + 磁盘 MB × 100（同一量纲，只用于排序与判活）
        public List<CpuProc> Busy = new List<CpuProc>();
        public string PerfError = "";

        private static readonly Dictionary<string, PerformanceCounter> Cache = new Dictionary<string, PerformanceCounter>();
        private static long PcCached(string category, string counter)
        {
            string key = category + "|" + counter;
            try
            {
                PerformanceCounter pc;
                if (!Cache.TryGetValue(key, out pc))
                {
                    pc = new PerformanceCounter(category, counter, true);
                    pc.NextValue();
                    Cache[key] = pc;
                }
                return (long)(pc.NextValue() / (1024.0 * 1024.0));
            }
            catch { return -1; }
        }

        // ★ 速率型计数器（次/秒、百分比）绝不能背靠背连读两次。
        //   PerformanceCounter 算的是「两次读数的差值 ÷ 时间间隔」，
        //   间隔几乎是 0 时算出来就是垃圾。
        //   实测：连读两次得到的 CPU 占用率是 96.6%，而同一时刻
        //   Get-Counter 读到的真实值是 29% —— 差了三倍多。
        //   所以这里强制：两次有效读数之间至少隔 1 秒；
        //   间隔不够就沿用上一次的值，首次读数直接返回 -1（表示暂无数据）。
        private static readonly Dictionary<string, DateTime> PcLastTime = new Dictionary<string, DateTime>();
        private static readonly Dictionary<string, double> PcLastVal = new Dictionary<string, double>();
        private static double PcRate(string category, string counter, string instance)
        {
            string key = category + "|" + counter + "|" + (instance == null ? "" : instance);
            try
            {
                PerformanceCounter pc;
                DateTime last;
                if (!Cache.TryGetValue(key, out pc))
                {
                    pc = instance == null
                        ? new PerformanceCounter(category, counter, true)
                        : new PerformanceCounter(category, counter, instance, true);
                    pc.NextValue();                 // 预热：速率型第一次读必然没有意义
                    Cache[key] = pc;
                    PcLastTime[key] = DateTime.Now;
                    PcLastVal[key] = -1;
                    return -1;                      // 首次返回 -1，调用方按「暂无数据」处理
                }
                if (PcLastTime.TryGetValue(key, out last)
                    && (DateTime.Now - last).TotalMilliseconds < 900)
                {
                    double prev;
                    return PcLastVal.TryGetValue(key, out prev) ? prev : -1;
                }
                double v = pc.NextValue();
                PcLastTime[key] = DateTime.Now;
                PcLastVal[key] = v;
                return v;
            }
            catch { return -1; }
        }

        // 速率型计数器（次/秒、百分比）不能用上面的 MB 换算
        private static double PcRaw(string category, string counter)
        {
            return PcRate(category, counter, null);
        }

        // 需要指定实例名（如 _Total）的计数器
        private static double PcInstance(string category, string counter)
        {
            return PcRate(category, counter, "_Total");
        }

        // 进程级 CPU 与磁盘读写：都靠两次采样的差值算速率。
        //
        // ★ 这里刻意不用 .NET 的 Process.TotalProcessorTime：本机 421 个进程它要 7 秒，
        //   而采样间隔只有 5 秒 —— 程序自己就成了最大的卡顿来源。
        //   改用 GetProcessTimes，同样的数据只要 30~60 毫秒，数值与 .NET 完全一致
        //   （实测逐个进程比值 1.0000）。
        private static Dictionary<int, TimeSpan> lastCpu = new Dictionary<int, TimeSpan>();
        private static DateTime lastCpuTime = DateTime.MinValue;
        private static Dictionary<int, ulong> lastIo = new Dictionary<int, ulong>();
        private static DateTime lastIoTime = DateTime.MinValue;

        // 每进程 CPU 占用与磁盘读写速率：一趟遍历同时取两个计数器，
        // 都靠两次采样的差值算速率。
        //
        // 只开 PROCESS_QUERY_LIMITED_INFORMATION（0x1000）就够：
        // 加上 PROCESS_QUERY_INFORMATION（0x400）反而让受保护进程全部打开失败
        // （实测开权限多反而少拿到 13 个进程），速度也没有区别。
        private static void TakePerProcess(Sample s)
        {
            List<CpuProc> cpuList = new List<CpuProc>();
            List<CpuProc> diskList = new List<CpuProc>();
            Dictionary<int, TimeSpan> nextCpu = new Dictionary<int, TimeSpan>();
            Dictionary<int, ulong> nextIo = new Dictionary<int, ulong>();
            // 本窗口每个进程「真的消耗了多少」——判断进程是不是在干活就靠它。
            // CPU 记毫秒、磁盘记 MB×100（磁盘权重更高：读写盘对系统流畅度的影响更直接），
            // 两者相加后只用于排序和「是否超过活动门槛」。
            Dictionary<int, double> busyById = new Dictionary<int, double>();
            Dictionary<int, string> nameById = new Dictionary<int, string>();
            Dictionary<string, double> cpuByName = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, double> diskByName = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);

            DateTime now = DateTime.Now;
            double wallCpu = (now - lastCpuTime).TotalSeconds;
            double wallIo = (now - lastIoTime).TotalSeconds;
            // ★ 采样窗口至少要 0.5 秒才换算速率。
            //   否则 BuildReport 里连续几次 Take() 会让窗口缩到几毫秒，
            //   2MB 的差值除以 0.001 秒就成了 2000 MB/s 这种天文数字
            //   （实测真的输出过「node 1946.0 MB/s」）。
            //   窗口太短时只更新基线、不算速率。
            const double MinWindow = 0.5;
            bool haveCpu = lastCpuTime != DateTime.MinValue;
            bool haveIo = lastIoTime != DateTime.MinValue;
            bool canCpu = haveCpu && wallCpu >= MinWindow;
            bool canIo = haveIo && wallIo >= MinWindow;
            int cores = Environment.ProcessorCount;
            if (cores < 1) cores = 1;

            foreach (Process p in Process.GetProcesses())
            {
                IntPtr h = IntPtr.Zero;
                try
                {
                    nameById[p.Id] = p.ProcessName;
                    h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
                    if (h == IntPtr.Zero) continue;

                    long create, exit, kernel, user;
                    if (Native.GetProcessTimes(h, out create, out exit, out kernel, out user))
                    {
                        // 单位 100 纳秒 → 毫秒
                        TimeSpan cur = TimeSpan.FromMilliseconds((kernel + user) / 10000.0);
                        nextCpu[p.Id] = cur;
                        if (canCpu)
                        {
                            TimeSpan prev;
                            if (lastCpu.TryGetValue(p.Id, out prev))
                            {
                                // 占用率 = 本窗口消耗的 CPU 时间 / (窗口时长 × 核心数)
                                double pct = (cur - prev).TotalMilliseconds / (wallCpu * 10.0 * cores);
                                // 本窗口消耗的 CPU 毫秒（与磁盘合并成「活跃度」）
                                double ms = (cur - prev).TotalMilliseconds;
                                if (ms > 0)
                                {
                                    double b0;
                                    busyById.TryGetValue(p.Id, out b0);
                                    busyById[p.Id] = b0 + ms;
                                }
                                if (pct >= 1)   // 1% 以下不列
                                {
                                    double old;
                                    if (cpuByName.TryGetValue(p.ProcessName, out old)) cpuByName[p.ProcessName] = old + pct;
                                    else cpuByName[p.ProcessName] = pct;
                                }
                            }
                        }
                    }

                    Native.IO_COUNTERS io;
                    if (Native.GetProcessIoCounters(h, out io))
                    {
                        ulong bytes = io.ReadTransferCount + io.WriteTransferCount;
                        nextIo[p.Id] = bytes;
                        if (canIo)
                        {
                            ulong prev;
                            if (lastIo.TryGetValue(p.Id, out prev) && bytes >= prev)
                            {
                                double mbps = (bytes - prev) / 1048576.0 / wallIo;
                                // 磁盘读写的「活跃度」权重 ×100：一次 1MB/s 的持续读写
                                // 对卡顿的贡献远大于 1 毫秒的 CPU 时间。
                                double mb = (bytes - prev) / 1048576.0;
                                if (mb > 0)
                                {
                                    double b1;
                                    busyById.TryGetValue(p.Id, out b1);
                                    busyById[p.Id] = b1 + mb * 100.0;
                                }
                                if (mbps >= 0.5)
                                {
                                    double old;
                                    if (diskByName.TryGetValue(p.ProcessName, out old)) diskByName[p.ProcessName] = old + mbps;
                                    else diskByName[p.ProcessName] = mbps;
                                }
                            }
                        }
                    }
                }
                catch { }
                finally
                {
                    if (h != IntPtr.Zero) Native.CloseHandle(h);
                    try { p.Dispose(); } catch { }
                }
            }

            // 窗口太短时不刷新基线，让窗口继续累积到足够长，
            // 否则「每秒刷新状态窗口」会把窗口永远压在几毫秒，速率永远是空的。
            if (!haveCpu || canCpu) { lastCpu = nextCpu; lastCpuTime = now; }
            if (!haveIo || canIo) { lastIo = nextIo; lastIoTime = now; }

            // 同名进程合并（node 常开几十个，不合并的话前几名全是 node）
            foreach (KeyValuePair<string, double> kv in cpuByName)
            {
                CpuProc c = new CpuProc();
                c.Name = kv.Key;
                c.Pct = kv.Value;
                cpuList.Add(c);
            }
            foreach (KeyValuePair<string, double> kv in diskByName)
            {
                CpuProc c = new CpuProc();
                c.Name = kv.Key;
                c.Pct = kv.Value;
                diskList.Add(c);
            }
            cpuList.Sort(delegate (CpuProc a, CpuProc b) { return b.Pct.CompareTo(a.Pct); });
            diskList.Sort(delegate (CpuProc a, CpuProc b) { return b.Pct.CompareTo(a.Pct); });
            s.TopCpu = cpuList;
            s.TopDisk = diskList;

            // 本窗口「在干活」的进程清单。注意这里按「进程 ID」而不是进程名：
            // node 常开几十个，其中几个在跑、其余空闲 —— 按名字合并会让整类
            // node 都显得很忙，正是用户抱怨的「firefox / node 我明明要用」的根源。
            List<CpuProc> busyList = new List<CpuProc>();
            foreach (KeyValuePair<int, double> kv in busyById)
            {
                string nm;
                if (!nameById.TryGetValue(kv.Key, out nm)) continue;
                CpuProc c = new CpuProc();
                c.Name = nm;
                c.Pct = kv.Value;      // 复用 Pct 承载「活跃度」，不做展示
                c.Id = kv.Key;
                busyList.Add(c);
            }
            busyList.Sort(delegate (CpuProc a, CpuProc b) { return b.Pct.CompareTo(a.Pct); });
            s.Busy = busyList;
        }

        // ★ Take() 会被多个线程同时调用：定时器（每 5 秒）、
        //   状态窗口的 RefreshLive 后台线程（每秒）、命令行预热。
        //   而「性能计数器」和「上次采样基线」都是共享状态：
        //   两个线程同时读同一个计数器，算出的差值间隔接近 0，
        //   百分比就会变成 96% 这种离谱数字（实测踩过）。
        //   所以整个采样过程串行化。
        private static readonly object TakeGate = new object();

        public static Sample Take()
        {
            lock (TakeGate) return TakeCore();
        }

        private static Sample TakeCore()
        {
            Sample s = new Sample();
            s.Time = DateTime.Now;
            try { s.UptimeHours = Math.Round((DateTime.Now - Boot).TotalHours, 2); } catch { s.UptimeHours = 0; }

            try
            {
                Native.MEMORYSTATUSEX m = new Native.MEMORYSTATUSEX();
                if (Native.GlobalMemoryStatusEx(m))
                {
                    s.TotalMB = (long)(m.ullTotalPhys / 1048576);
                    s.AvailMB = (long)(m.ullAvailPhys / 1048576);
                    long limit = (long)(m.ullTotalPageFile / 1048576);
                    long availPF = (long)(m.ullAvailPageFile / 1048576);
                    s.CommitLimitMB = limit;
                    s.CommitMB = limit - availPF;
                    s.CommitPct = limit > 0 ? (long)Math.Round(100.0 * s.CommitMB / limit) : 0;
                }
            }
            catch { }

            s.PoolNonPagedMB = PcCached("Memory", "Pool Nonpaged Bytes");
            s.PoolPagedMB = PcCached("Memory", "Pool Paged Bytes");
            s.StandbyMB = PcCached("Memory", "Standby Cache Normal Priority Bytes");
            s.ModifiedMB = PcCached("Memory", "Modified Page List Bytes");

            if (s.PoolNonPagedMB < 0 || s.PoolPagedMB < 0) s.PerfError = "性能计数器不可用";

            // 换页压力：Pages Input/sec 是「必须去读硬盘才能拿到」的硬缺页，最能说明内存不够用
            s.PageFaultsPerSec = PcRaw("Memory", "Page Faults/sec");
            s.HardFaultsPerSec = PcRaw("Memory", "Pages Input/sec");
            s.DpcPct = PcInstance("Processor Information", "% DPC Time");
            s.InterruptPct = PcInstance("Processor Information", "% Interrupt Time");
            s.CpuPct = PcInstance("Processor Information", "% Processor Time");
            // 磁盘：% Disk Time 在 NVMe 上可能超过 100（多队列并行），仅作参考；
            // 队列长度和吞吐量更能说明「是不是磁盘在拖后腿」。
            s.DiskBusyPct = PcInstance("PhysicalDisk", "% Disk Time");
            s.DiskQueue = PcInstance("PhysicalDisk", "Current Disk Queue Length");
            double db = PcInstance("PhysicalDisk", "Disk Bytes/sec");
            s.DiskMBps = db < 0 ? -1 : db / 1048576.0;
            TakePerProcess(s);

            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        s.Procs++;
                        s.Threads += p.Threads.Count;
                        s.Handles += p.HandleCount;
                        if (p.ProcessName == "Memory Compression") s.CompressionMB = p.WorkingSet64 / 1048576;
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
            return s;
        }
    }

    // ==================== 整理结果 ====================
    internal class TrimResult
    {
        public int Trimmed, Failed;
        // 「正在用 / 在干活 / 刚整理过」而主动跳过的数量（不是失败，是保护）
        public int SkippedUsing, SkippedBusy, SkippedRecent;
        public long BeforeAvailMB, AfterAvailMB;
        public string Trigger = "";
        public long FreedMB { get { return AfterAvailMB - BeforeAvailMB; } }
    }

    // ==================== 内存整理器 ====================
    internal static class Trimmer
    {
        private static readonly string[] Protected = new string[] {
            "System","Idle","Registry","Memory Compression","csrss","wininit","winlogon","services",
            "lsass","smss","dwm","audiodg","fontdrvhost","Secure System","LsaIso","conhost",
            "sihost","SmoothWinTray","WUDFHost","SecurityHealthService","MpDefenderCoreService"
        };

        // 无论多激进都绝不触碰的核心集。深度整理若把 dwm/csrss 的工作集清掉，
        // 会立刻造成一次可见的卡顿——那就成了「为了治卡而制造卡」。
        private static readonly string[] CoreProtected = new string[] {
            "System","Idle","Registry","Memory Compression","csrss","wininit","winlogon","services",
            "lsass","smss","dwm","audiodg","fontdrvhost","Secure System","LsaIso","SmoothWinTray"
        };

        internal static bool InList(string[] list, string name)
        {
            foreach (string n in list) if (string.Equals(n, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static bool IsAdmin
        {
            get
            {
                try
                {
                    using (System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent())
                        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
                catch { return false; }
            }
        }

        public static int ForegroundPid()
        {
            try
            {
                int pid;
                Native.GetWindowThreadProcessId(Native.GetForegroundWindow(), out pid);
                return pid;
            }
            catch { return 0; }
        }

        // ★ 每个进程上次被整理的时间：同一个进程短时间内绝不重复整理。
        //   反复把同一批页推出去，它们下次被访问时又要从 pagefile 读回来，
        //   硬缺页不但降不下来，反而被自己顶高（本机实测过这个自激环路）。
        private static readonly Dictionary<int, DateTime> lastTrimPid = new Dictionary<int, DateTime>();

        // 「正在干活」的门槛：一个采样窗口里消耗了多少才算「在用」。
        // 活跃度 = CPU 毫秒 + 磁盘 MB × 100（算法见 Sample.Busy）。
        // 5 秒窗口里 200 毫秒 CPU 约等于单核 4%；低于它的进程基本只是
        // 「开着」而不是「在用」——这一类才是该整理的对象。
        private const double BusyThreshold = 200.0;

        public static TrimResult Run(Config cfg, string trigger, bool aggressive)
        {
            TrimResult r = new TrimResult();
            r.Trigger = trigger;
            Sample before = Sample.Take();
            r.BeforeAvailMB = before.AvailMB;

            // 第一次采样没有基线，Busy 表是空的 —— 那样本次整理就失去了「谁在干活」
            // 的判据，正是最需要保护的那一次反而没保护。补一个短窗口采样再判活。
            if (before == null || before.Busy == null || before.Busy.Count == 0)
            {
                Thread.Sleep(700);
                Sample again = Sample.Take();
                if (again != null && again.Busy != null && again.Busy.Count > 0) before = again;
            }

            Native.EnablePrivilege("SeProfileSingleProcessPrivilege");
            Native.EnablePrivilege("SeIncreaseQuotaPrivilege");

            // ★ 默认不再强制把已修改页面写盘。这个动作会把 dirty page 立刻推进
            //   pagefile，制造一段读盘高峰，用户感受到的就是「整理完更卡了」。
            //   只有配置里显式打开（AggressiveFlushModified=true）才做。
            if (aggressive && cfg.AggressiveFlushModified)
            {
                int rc = Native.MemoryList(Native.MemoryFlushModifiedList);
                Log.Write("刷新已修改页面列表 返回=" + rc);
            }

            // ---- 判断「谁在用」的三张表 ----
            // ① 前台进程：用户正在操作的窗口，绝对不碰。
            int fg = ForegroundPid();
            int me = Process.GetCurrentProcess().Id;
            // ② 有可见且未最小化窗口的进程：用户正开着界面，不动。
            HashSet<int> shown = Native.VisibleWindowPids();
            // ③ 本窗口里真在干活的进程：Pct 就是活跃度（见 Sample.Busy）。
            Dictionary<int, double> busy = new Dictionary<int, double>();
            try
            {
                if (before != null && before.Busy != null)
                    foreach (CpuProc c in before.Busy) busy[c.Id] = c.Pct;
            }
            catch { }

            List<Process> targets = new List<Process>();
            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.Id <= 4 || p.Id == fg || p.Id == me) { p.Dispose(); continue; }
                        // 核心集永远跳过，与 aggressive 无关
                        if (InList(CoreProtected, p.ProcessName)) { p.Dispose(); continue; }
                        if (!aggressive && InList(Protected, p.ProcessName)) { p.Dispose(); continue; }
                        if (p.WorkingSet64 < (long)cfg.MinTrimMB * 1048576L) { p.Dispose(); continue; }

                        // ★ 用户明确要求：firefox / node 这些「我还要用」的程序不能碰。
                        //   判据不是进程名，而是它此刻的状态 ——
                        //   同一个 node.exe，跑任务的那个不动，闲置的那个照常整理。
                        if (cfg.TrimIdleOnly)
                        {
                            // 有可见窗口 = 用户开着界面，算「在用」
                            if (shown.Contains(p.Id)) { r.SkippedUsing++; p.Dispose(); continue; }
                            // 本窗口真的在消耗 CPU / 磁盘 = 在干活，算「在用」
                            double act;
                            if (busy.TryGetValue(p.Id, out act) && act >= BusyThreshold)
                            { r.SkippedBusy++; p.Dispose(); continue; }
                        }

                        // ★ 同一个进程在冷却期内不重复整理
                        DateTime lastT;
                        if (lastTrimPid.TryGetValue(p.Id, out lastT)
                            && (DateTime.Now - lastT) < TimeSpan.FromSeconds(Math.Max(0, cfg.TrimCooldownSeconds)))
                        { r.SkippedRecent++; p.Dispose(); continue; }

                        targets.Add(p);
                    }
                    catch { try { p.Dispose(); } catch { } }
                }
            }
            catch { }

            foreach (Process p in targets)
            {
                IntPtr h = IntPtr.Zero;
                try
                {
                    h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION | Native.PROCESS_SET_QUOTA, false, p.Id);
                    if (h == IntPtr.Zero) { r.Failed++; continue; }
                    if (Native.EmptyWorkingSet(h)) { r.Trimmed++; lastTrimPid[p.Id] = DateTime.Now; }
                    else r.Failed++;
                }
                catch { r.Failed++; }
                finally { if (h != IntPtr.Zero) Native.CloseHandle(h); try { p.Dispose(); } catch { } }
            }

            // 进程 ID 会被复用，这张表留太大反而会误判冷却，定期清一次
            try { if (lastTrimPid.Count > 4096) lastTrimPid.Clear(); } catch { }

            Thread.Sleep(600);
            r.AfterAvailMB = Sample.Take().AvailMB;
            return r;
        }
    }

    // ==================== 历史记录 ====================
    internal static class History
    {
        private static readonly object Gate = new object();
        // -1 表示计数器不可用，写成空字段而不是负数，方便直接丢进 Excel 画图
        private static string Num(double v)
        {
            return v < 0 ? "" : Math.Round(v, 1).ToString(CultureInfo.InvariantCulture);
        }
        // 表头：列数变了就要跟着改。以前只在「文件不存在」时写表头，
        // 结果升级后数据行有 21 列、表头还停在 14 列，Excel 里一打开就是错位的。
        internal const string Header = "时间,已运行小时,可用MB,提交MB,提交上限MB,提交%,非分页池MB,分页池MB,待机MB,已修改MB,内存压缩MB,进程,线程,句柄,硬缺页每秒,DPC百分比,中断百分比,CPU百分比,磁盘繁忙%,磁盘队列,磁盘MB每秒";

        // 表头对不上时，保留全部数据行、只把表头换成新的
        private static void FixHeader()
        {
            try
            {
                if (!File.Exists(Config.HistoryPath)) return;
                string[] lines = File.ReadAllLines(Config.HistoryPath);
                if (lines.Length == 0 || lines[0] == Header) return;
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(Header);
                for (int i = 1; i < lines.Length; i++)
                    if (lines[i].Length > 0) sb.AppendLine(lines[i]);
                File.WriteAllText(Config.HistoryPath, sb.ToString(), new UTF8Encoding(true));
            }
            catch { }
        }

        public static void Append(Sample s)
        {
            try
            {
                lock (Gate)
                {
                    bool isNew = !File.Exists(Config.HistoryPath);
                    if (!isNew) FixHeader();
                    StringBuilder sb = new StringBuilder();
                    if (isNew)
                        sb.AppendLine(Header);
                    sb.AppendLine(string.Join(",", new string[] {
                        s.Time.ToString("yyyy-MM-dd HH:mm:ss"), s.UptimeHours.ToString(CultureInfo.InvariantCulture),
                        s.AvailMB.ToString(), s.CommitMB.ToString(), s.CommitLimitMB.ToString(), s.CommitPct.ToString(),
                        s.PoolNonPagedMB.ToString(), s.PoolPagedMB.ToString(), s.StandbyMB.ToString(), s.ModifiedMB.ToString(),
                        s.CompressionMB.ToString(), s.Procs.ToString(), s.Threads.ToString(), s.Handles.ToString(),
                        Num(s.HardFaultsPerSec), Num(s.DpcPct), Num(s.InterruptPct),
                        Num(s.CpuPct), Num(s.DiskBusyPct), Num(s.DiskQueue), Num(s.DiskMBps)
                    }));
                    File.AppendAllText(Config.HistoryPath, sb.ToString(), new UTF8Encoding(true));
                }
            }
            catch { }
        }
    }

    // ==================== 事件计数 ====================
    internal static class Events
    {
        // ★ 实测：一次 Count() 要 300 毫秒（EventLogQuery 的 XPath 是全表扫描），
        //   而报告里要连问 4 次 = 1.2 秒。状态窗口每秒刷新一次，
        //   UI 线程每轮都被卡住 1.2 秒 —— 这正是窗口「未响应」的直接原因。
        //   「近 24 小时崩了几次」是慢变量，缓存 10 分钟完全够用。
        private static readonly object Gate = new object();
        private static readonly Dictionary<string, int> CountCache = new Dictionary<string, int>();
        private static readonly Dictionary<string, DateTime> CountTime = new Dictionary<string, DateTime>();
        private const int CacheMinutes = 10;

        public static int Count(string provider, int id, int hours)
        {
            string key = provider + "|" + id + "|" + hours;
            lock (Gate)
            {
                int hit; DateTime t;
                if (CountCache.TryGetValue(key, out hit)
                    && CountTime.TryGetValue(key, out t)
                    && (DateTime.Now - t) < TimeSpan.FromMinutes(CacheMinutes))
                    return hit;
            }
            int n = CountUncached(provider, id, hours);
            if (n >= 0)   // 失败不缓存，下次还会重试
            {
                lock (Gate) { CountCache[key] = n; CountTime[key] = DateTime.Now; }
            }
            return n;
        }

        private static int CountUncached(string provider, int id, int hours)
        {
            try
            {
                long ms = (long)hours * 3600000L;
                string xpath = "*[System[Provider[@Name='" + provider + "'] and EventID=" + id +
                               " and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]";
                EventLogQuery q = new EventLogQuery("System", PathType.LogName, xpath);
                q.TolerateQueryErrors = true;
                int n = 0;
                using (EventLogReader rd = new EventLogReader(q))
                {
                    while (rd.ReadEvent() != null) n++;
                }
                return n;
            }
            catch { return -1; }
        }

        public static DateTime LastTdrTime()
        {
            try
            {
                string xpath = "*[System[Provider[@Name='Display'] and EventID=4101]]";
                EventLogQuery q = new EventLogQuery("System", PathType.LogName, xpath);
                q.TolerateQueryErrors = true;
                q.ReverseDirection = true;
                using (EventLogReader rd = new EventLogReader(q))
                {
                    EventRecord e = rd.ReadEvent();
                    if (e != null && e.TimeCreated.HasValue) return e.TimeCreated.Value;
                }
            }
            catch { }
            return DateTime.MinValue;
        }
    }

    // ==================== 有问题的设备 ====================
    // 「用久了越来越卡」的常见源头之一，是某个设备驱动根本没装好，系统反复重试。
    // 这件事程序修不了（需要厂商驱动包），但必须能查出来并明确告诉用户去装什么。
    internal class BadDevice
    {
        internal const string BACKSLASH = "\\";   // 避免在字符串里写双反斜杠

        public string Instance, Name, Cls;
        public int Problem;
        public string Meaning { get { return MeaningOf(Problem); } }
        public string MeaningShort
        {
            get { return MeaningOf(Problem).Replace("★", "").Trim(); }
        }

        // 没有 FriendlyName 的设备（驱动没装的都这样）显示成「厂商 + 类别」，
        // 比如「AMD USB 控制器」「MediaTek 网络适配器」——裸的实例 ID 用户看不懂。
        public string Display
        {
            get
            {
                // 先查已知硬件 ID 表：Windows 给没装驱动的设备起的名字都是
                // GenericAdapter / (标准系统设备) 这类废话，直接显示反而让人看不懂。
                string known = KnownDevice(Instance);
                if (known.Length > 0) return known;
                if (!string.IsNullOrEmpty(Name) && Name != Instance && !IsPlaceholder(Name)) return Name;
                string v = VendorOf(Instance);
                string c = ClassCn(Cls);
                if (v.Length > 0 && c.Length > 0) return v + " " + c;
                if (c.Length > 0) return c;
                if (v.Length > 0) return v + " 设备";
                return Instance;
            }
        }

        // Windows 在拿不到真实设备名时给的占位文本，显示出来毫无信息量
        public static bool IsPlaceholder(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            string s = name.Trim();
            if (s == "GenericAdapter" || s == "Generic Device" || s == "Unknown") return true;
            if (s.Length >= 2 && s[0] == '(' && s[s.Length - 1] == ')') return true;   // 「(标准系统设备)」
            return false;
        }

        // 常见设备的「人话名字」。没装驱动时 Windows 查不到类别，
        // 只能靠硬件 ID 认——这张表覆盖这台机器上实际出现的那些。
        public static string KnownDevice(string instance)
        {
            try
            {
                string s = (instance ?? "").ToUpperInvariant();
                if (s.Contains("VEN_14C3&DEV_7961")) return "MediaTek Wi-Fi 6E 无线网卡";
                if (s.Contains("VEN_1022&DEV_1668")) return "AMD USB 3.1 控制器";
                if (s.Contains("VEN_1022&DEV_1669")) return "AMD USB 3.1 控制器";
                if (s.Contains("VEN_1022&DEV_164A")) return "AMD 芯片组（PCI 桥）";
                if (s.Contains("VEN_1022&DEV_15C7")) return "AMD 芯片组（PCI 桥）";
                if (s.Contains("VEN_1022&DEV_14EC")) return "AMD 芯片组（PSP 安全处理器）";
                if (s.Contains("VEN_1022&DEV_14ED")) return "AMD 芯片组（SMBus 控制器）";
                if (s.Contains("VEN_1022&DEV_15E2")) return "AMD 音频协处理器";
                if (s.Contains("VEN_1022&DEV_1649")) return "AMD 芯片组（PCI 桥）";
                if (s.Contains("VEN_1022&DEV_14E8")) return "AMD 芯片组（GPIO 控制器）";
                if (s.Contains("VEN_1022&DEV_15D4")) return "AMD 芯片组（SMBus 控制器）";
                if (s.Contains("ACPI" + BACKSLASH + "AMDI0052")) return "AMD 音频协处理器（ACPI）";
                if (s.Contains("VID_0489&PID_E0C8")) return "Foxconn 蓝牙模块";
                if (s.Contains("ROOT" + BACKSLASH + "MEDIA")) return "流媒体服务（非硬件）";
                return "";
            }
            catch { return ""; }
        }

        public static string VendorOf(string instance)
        {
            try
            {
                string s = (instance ?? "").ToUpperInvariant();
                int i = s.IndexOf("VEN_");
                if (i < 0) i = s.IndexOf("VID_");
                if (i < 0) return "";
                if (i + 8 > s.Length) return "";
                string id = s.Substring(i + 4, 4);
                switch (id)
                {
                    case "1022": return "AMD";
                    case "1002": return "AMD";
                    case "14C3": return "MediaTek";
                    case "8086": return "Intel";
                    case "10DE": return "NVIDIA";
                    case "10EC": return "Realtek";
                    case "14E4": return "Broadcom";
                    case "1B21": return "ASMedia";
                    case "1D6B": return "Linux 内核";
                    case "0489": return "Foxconn";
                    case "0BDA": return "Realtek";
                    case "1025": return "Acer";
                    case "1028": return "Dell";
                    case "103C": return "HP";
                    case "1043": return "ASUS";
                    case "17AA": return "Lenovo";
                    case "1558": return "蓝天/Clevo";
                    default: return "厂商 " + id;
                }
            }
            catch { return ""; }
        }

        public static string ClassCn(string cls)
        {
            switch (cls)
            {
                case "USB": return "USB 控制器";
                case "Net": return "网络适配器";
                case "MEDIA": return "音频设备";
                case "AudioEndpoint": return "音频设备";
                case "Display": return "显示适配器";
                case "HDC": return "存储控制器";
                case "SCSIAdapter": return "存储控制器";
                case "System": return "系统设备";
                case "Processor": return "处理器";
                case "Bluetooth": return "蓝牙";
                case "Keyboard": return "键盘";
                case "Mouse": return "鼠标";
                case "Monitor": return "显示器";
                case "Camera": return "摄像头";
                case "Firmware": return "固件";
                case "SoftwareDevice": return "软件设备";
                case "SecurityDevices": return "安全设备";
                default: return cls;
            }
        }

        public static string MeaningOf(int code)
        {
            switch (code)
            {
                case 1: return "设备未配置";
                case 3: return "驱动已损坏";
                case 9: return "设备信息无效";
                case 10: return "设备无法启动";
                case 12: return "资源不足（设备之间抢资源）";
                case 14: return "需要重启电脑才能生效";
                case 16: return "资源不完整";
                case 18: return "需要重新安装驱动";
                case 19: return "注册表里的驱动配置损坏";
                case 21: return "系统正在移除该设备";
                case 22: return "设备已被禁用";
                case 24: return "设备未安装（或未接入）";
                case 28: return "驱动没有安装 ★";
                case 31: return "Windows 无法加载这个设备的驱动 ★";
                case 37: return "驱动无法初始化 ★";
                case 43: return "驱动报告设备故障（被系统停用）★";
                case 45: return "设备当前未接入";
                default: return "代码 " + code;
            }
        }
    }

    internal static class Devices
    {
        private static string Prop(int devInst, int prop)
        {
            try
            {
                int len = 512;
                StringBuilder sb = new StringBuilder(len);
                int type;
                if (Native.CM_Get_DevNode_Registry_Property(devInst, prop, out type, sb, ref len, 0) != 0) return "";
                return sb.ToString();
            }
            catch { return ""; }
        }

        // 只列「真的有问题的」：拔掉的 U 盘、蓝牙未连接这类不算，它们不是卡顿原因。
        public static List<BadDevice> Scan()
        {
            List<BadDevice> list = new List<BadDevice>();
            try
            {
                // 注意：这里刻意不加 CM_GETIDLIST_FILTER_PRESENT 过滤。
                // 「驱动没装好」的设备（代码 28/31）恰恰不在「当前存在」列表里，
                // 加了这个过滤会一个都扫不到 —— 实测确认过（返回 0 个）。
                int len;
                if (Native.CM_Get_Device_ID_List_Size(out len, null, 0) != 0) return list;
                char[] buf = new char[len];
                if (Native.CM_Get_Device_ID_List(null, buf, len, 0) != 0) return list;

                // 返回的是一整块「以 \0 分隔的字符串 + 结尾双 \0」，
                // 不能用 StringBuilder 接（会被截断到第一个 \0），必须手工拆。
                List<string> ids = new List<string>();
                StringBuilder cur = new StringBuilder();
                foreach (char ch in buf)
                {
                    if (ch == '\0') { if (cur.Length > 0) { ids.Add(cur.ToString()); cur.Length = 0; } }
                    else cur.Append(ch);
                }
                if (cur.Length > 0) ids.Add(cur.ToString());

                foreach (string id in ids)
                {
                    int devInst;
                    if (Native.CM_Locate_DevNode(out devInst, id, 0) != 0) continue;
                    int status, problem;
                    if (Native.CM_Get_DevNode_Status(out status, out problem, devInst, 0) != 0) continue;
                    if (problem == 0) continue;

                    string name = Prop(devInst, Native.SPDRP_FRIENDLYNAME);
                    if (name.Length == 0) name = Prop(devInst, Native.SPDRP_DEVICEDESC);
                    string cls = Prop(devInst, Native.SPDRP_CLASS);
                    list.Add(new BadDevice { Instance = id, Name = name, Cls = cls, Problem = problem });
                }
            }
            catch { }
            return list;
        }

        // 挑出「最可能就是卡顿源头」的那几个：USB 控制器、PCI 设备、存储控制器、网卡、芯片组
        public static bool IsLikelyCause(BadDevice d)
        {
            if (d.Problem != 28 && d.Problem != 31 && d.Problem != 43 && d.Problem != 10 && d.Problem != 37) return false;
            // 按设备类别判断，比字符串猜更准：
            // USB/网络/音频/存储/显示/芯片组(System) 出问题会直接影响使用；
            // 键盘鼠标显示器这类外设的异常不影响系统性能，不列进来制造焦虑。
            string c = d.Cls ?? "";
            switch (c)
            {
                case "USB":
                case "Net":
                case "MEDIA":
                case "AudioEndpoint":
                case "HDC":
                case "SCSIAdapter":
                case "System":
                case "Bluetooth":
                case "Display":
                case "Firmware":
                case "SecurityDevices":
                    return true;
            }
            string s = (d.Instance ?? "").ToLowerInvariant();
            if (s.Contains("pci\\ven_") || s.Contains("acpi\\") || s.Contains("usb\\vid_")) return true;
            return false;
        }

        public static string Summary()
        {
            List<BadDevice> all = Scan();
            List<BadDevice> hit = new List<BadDevice>();
            foreach (BadDevice d in all) if (IsLikelyCause(d)) hit.Add(d);
            if (all.Count == 0) return "没有发现问题的设备";

            StringBuilder b = new StringBuilder();
            b.Append(hit.Count > 0 ? "发现 " + hit.Count + " 个可能有影响的设备" : "发现 " + all.Count + " 个异常设备（多为未接入的外设，可忽略）");
            List<string> seen = new List<string>();
            int n = 0;
            foreach (BadDevice d in hit)
            {
                if (n >= 3) break;
                if (seen.Contains(d.Display)) continue;   // 同类设备只列一次，不然全是重复
                seen.Add(d.Display);
                n++;
                b.Append("；").Append(d.Display).Append("（").Append(d.MeaningShort).Append("）");
            }
            return b.ToString();
        }

        // 结论卡用的短版：先把「这是什么问题」说清楚，
        // 只列前几个设备 +「还有 N 个」，剩下的引导去看「详细报告」。
        // 之前直接用全文，设备清单一长就把解释挤没了，卡片截断在半句话上。
        public static string Brief()
        {
            List<BadDevice> all = Scan();
            List<BadDevice> hit = new List<BadDevice>();
            foreach (BadDevice d in all) if (IsLikelyCause(d)) hit.Add(d);
            if (hit.Count == 0) return "";

            List<string> seen = new List<string>();
            foreach (BadDevice d in hit) if (!seen.Contains(d.Display)) seen.Add(d.Display);

            StringBuilder b = new StringBuilder();
            b.Append("有 ").Append(hit.Count).Append(" 个设备的驱动没装好（设备管理器里有黄色感叹号）：").AppendLine();
            int n = 0;
            foreach (string s in seen)
            {
                if (n >= 3) break;
                b.Append("  · ").Append(s).AppendLine();
                n++;
            }
            if (seen.Count > 3) b.Append("  · 还有 ").Append(seen.Count - 3).Append(" 个（见「详细报告」）").AppendLine();
            b.AppendLine();
            b.Append("这意味着什么：Windows 认得出这些设备，但没有能用的驱动程序。").AppendLine();
            b.Append("系统每次开机、每次重扫设备树都会再试一遍，试一次失败一次，").AppendLine();
            b.Append("有些设备还会让系统定期重扫 PCI 总线——这就是「没开几个程序、").AppendLine();
            b.Append("用久了却越来越卡」的常见来源之一。").AppendLine();
            b.Append("怎么处理：点下面「详细报告」看步骤（程序不替你下载、不替你改系统）。");
            return b.ToString();
        }

        // 完整的「怎么办」——这条只能由用户去装驱动，程序不能替他装
        public static string Advice()
        {
            List<BadDevice> all = Scan();
            List<BadDevice> hit = new List<BadDevice>();
            foreach (BadDevice d in all) if (IsLikelyCause(d)) hit.Add(d);
            if (hit.Count == 0) return "";

            StringBuilder b = new StringBuilder();
            b.Append("有 ").Append(hit.Count).Append(" 个设备的驱动没装好（设备管理器里有黄色感叹号）。").AppendLine();
            b.Append("系统会反复尝试加载它们，是「用久了越来越卡」的常见原因之一。").AppendLine();
            b.AppendLine();
            b.Append("受影响的设备：").AppendLine();
            List<string> seen = new List<string>();
            foreach (BadDevice d in hit)
            {
                if (seen.Contains(d.Display)) continue;
                seen.Add(d.Display);
                b.Append("  · ").Append(d.Display).Append("（").Append(d.MeaningShort).Append("）").AppendLine();
            }
            b.AppendLine();
            b.Append("这意味着什么：").AppendLine();
            b.Append("  Windows 认得出有这些设备，但没有能用的驱动程序。").AppendLine();
            b.Append("  于是系统每次开机、每次重扫设备树都会再试一遍，").AppendLine();
            b.Append("  试一次失败一次；有些设备还会让系统定期重扫 PCI 总线。").AppendLine();
            b.Append("  这就是「没开几个程序、用久了却越来越卡」的常见来源之一。").AppendLine();
            b.AppendLine();
            b.Append("怎么处理（程序不能替你装驱动，只能你自己装）：").AppendLine();
            b.Append("  · 打开「设备管理器」（Win+X → 设备管理器），凡是带黄色感叹号的").AppendLine();
            b.Append("    条目就是它。右键 →「属性」→「详细信息」→ 选「硬件 ID」，").AppendLine();
            b.Append("    把 VEN_ 和 DEV_ 这两个值记下来。").AppendLine();
            b.Append("  · 拿这两个 ID 去搜，或者在电脑/主板厂商的支持页面按机型找驱动。").AppendLine();
            b.Append("    一般来说：主板/芯片组那几项来自电脑或主板厂商，").AppendLine();
            b.Append("    显卡、网卡、蓝牙、音频各自来自对应芯片厂商。").AppendLine();
            b.Append("  · 装完重启一次，再回来点「重新检查」看这一行是否变成").AppendLine();
            b.Append("    「没有发现问题的设备」。").AppendLine();
            b.AppendLine();
            b.Append("本程序只负责把它查出来告诉你，不会替你下载、更不会替你改系统。");
            return b.ToString();
        }
    }

    // ==================== 开机自启项 ====================
    // 注意：这里**只读**，绝不自动禁用任何一项。
    // （用户之前被自动关掉自启项坑过——远控软件没了，没法远程重启机器。）
    // 这里的作用是让用户看清「到底有多少东西在跟着开机启动、各占多少内存」，
    // 由用户自己决定关哪个。这就是「降低常驻负载」那一步该做的事。
    internal class StartItem
    {
        public string Name, Cmd, Where;
        public string Exe;          // 可执行文件名（不带 .exe），用于匹配进程
        public long RunningMB = -1; // 正在运行时占的内存；-1 = 没在跑
        // 这一项是从哪儿读来的：HKCU / HKLM / HKLM32 / StartupFolder / CommonStartupFolder。
        // 启用、禁用都要靠它决定去动哪一个 StartupApproved 键。
        public string Source;
        public bool Enabled = true; // 下次开机还会不会自动启动

        public static string ExeNameOf(string cmd)
        {
            try
            {
                if (string.IsNullOrEmpty(cmd)) return "";
                string s = cmd.Trim();
                if (s.StartsWith("\""))
                {
                    int e = s.IndexOf('"', 1);
                    if (e > 1) s = s.Substring(1, e - 1);
                }
                else
                {
                    int sp = s.IndexOf(' ');
                    if (sp > 0 && !s.Substring(0, sp).ToUpperInvariant().EndsWith(".EXE")) { }
                    else if (sp > 0) s = s.Substring(0, sp);
                }
                string n = Path.GetFileName(s);
                if (n.ToLowerInvariant().EndsWith(".exe")) n = n.Substring(0, n.Length - 4);
                return n;
            }
            catch { return ""; }
        }
    }

    internal static class Startup
    {
        // 启动项的「开 / 关」状态不在 Run 键里，而在 Explorer 的 StartupApproved 里。
        // 任务管理器里点「禁用」就是往这里写一个二进制值；Run 键里的启动项本身一个字节都不动，
        // 所以随时能原样启用回来 —— 这正是我们要的：绝不删用户的自启项。
        private const string ApprovedRun = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
        private const string ApprovedRun32 = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
        private const string ApprovedFolder = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

        private static void Add(List<StartItem> list, string name, string cmd, string where, string source)
        {
            if (string.IsNullOrEmpty(cmd)) return;
            foreach (StartItem x in list) if (x.Cmd == cmd) return;   // 去重
            list.Add(new StartItem { Name = name, Cmd = cmd, Where = where, Source = source, Exe = StartItem.ExeNameOf(cmd) });
        }

        private static void ScanKey(List<StartItem> list, string path, string where, string source)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(path))
                {
                    if (k == null) return;
                    foreach (string n in k.GetValueNames())
                        Add(list, n, k.GetValue(n) as string, where, source);
                }
            }
            catch { }
        }

        private static void ScanKeyLm(List<StartItem> list, string path, string where, string source)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (k == null) return;
                    foreach (string n in k.GetValueNames())
                        Add(list, n, k.GetValue(n) as string, where, source);
                }
            }
            catch { }
        }

        public static List<StartItem> Scan()
        {
            List<StartItem> list = new List<StartItem>();
            ScanKey(list, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "当前用户", "HKCU");
            ScanKeyLm(list, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "所有用户", "HKLM");
            ScanKeyLm(list, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "所有用户(32位)", "HKLM32");

            try
            {
                string[] dirs = new string[] {
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
                };
                string[] tags = new string[] { "StartupFolder", "CommonStartupFolder" };
                for (int i = 0; i < dirs.Length; i++)
                {
                    string d = dirs[i];
                    if (!Directory.Exists(d)) continue;
                    foreach (string fp in Directory.GetFiles(d, "*.lnk"))
                        Add(list, Path.GetFileNameWithoutExtension(fp), fp, "启动文件夹", tags[i]);
                }
            }
            catch { }

            // 匹配当前正在跑的进程，顺便记下占用
            try
            {
                Dictionary<string, long> byName = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        long mb = p.WorkingSet64 / 1048576;
                        if (byName.ContainsKey(p.ProcessName)) byName[p.ProcessName] += mb;
                        else byName[p.ProcessName] = mb;
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
                foreach (StartItem it in list)
                {
                    long v;
                    if (it.Exe.Length > 0 && byName.TryGetValue(it.Exe, out v)) it.RunningMB = v;
                }
            }
            catch { }

            // 顺手把「启用 / 禁用」读出来：表格窗口每行都要显示状态，
            // 放在这里一次读完，省得每个调用点各查一遍注册表。
            foreach (StartItem it in list) it.Enabled = IsEnabled(it);

            list.Sort(delegate (StartItem a, StartItem b) { return b.RunningMB.CompareTo(a.RunningMB); });
            return list;
        }

        // ---------- 启用 / 禁用 ----------
        private static bool IsHkcu(StartItem it) { return it.Source == "HKCU" || it.Source == "StartupFolder"; }

        private static string ApprovedPath(StartItem it)
        {
            if (it.Source == "HKLM") return ApprovedRun;
            if (it.Source == "HKLM32") return ApprovedRun32;
            if (it.Source == "StartupFolder" || it.Source == "CommonStartupFolder") return ApprovedFolder;
            return ApprovedRun;
        }

        // 注册表启动项用「值名」；启动文件夹里的 .lnk 用「完整路径」当值名
        private static string ApprovedName(StartItem it)
        {
            if (it.Source == "StartupFolder" || it.Source == "CommonStartupFolder") return it.Cmd;
            return it.Name;
        }

        public static bool IsEnabled(StartItem it)
        {
            try
            {
                using (RegistryKey root = IsHkcu(it) ? Registry.CurrentUser : Registry.LocalMachine)
                using (RegistryKey k = root.OpenSubKey(ApprovedPath(it)))
                {
                    if (k == null) return true;                       // 没记录 = 启用
                    byte[] b = k.GetValue(ApprovedName(it)) as byte[];
                    if (b == null || b.Length == 0) return true;
                    return (b[0] & 1) == 1;                           // 02/06 = 已禁用；03/07 = 已启用
                }
            }
            catch { return true; }
        }

        public static bool SetEnabled(StartItem it, bool enable, out string err)
        {
            err = "";
            try
            {
                using (RegistryKey root = IsHkcu(it) ? Registry.CurrentUser : Registry.LocalMachine)
                using (RegistryKey k = root.CreateSubKey(ApprovedPath(it)))
                {
                    if (k == null) { err = "打不开启动项状态键（多半是权限不够）"; return false; }
                    string n = ApprovedName(it);
                    if (enable) k.DeleteValue(n, false);               // 没有记录 = 启用
                    else k.SetValue(n, new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);
                }
                return true;
            }
            catch (Exception ex) { err = ex.Message; return false; }
        }

        // 诊断（只给 --startupui 用）：把「读 / 可写打开 / 建子键 / 写值 / 删值」每一步单独跑一遍，
        // 分别报出结果与异常类型 —— 用来定位到底是哪一步被拒绝、被谁拒绝。
        private delegate string DiagStep();

        private static void DiagRun(StringBuilder b, string label, DiagStep f)
        {
            try { b.AppendLine("           " + label + " = " + f()); }
            catch (Exception ex)
            {
                b.AppendLine("           " + label + " = 异常 " + ex.GetType().Name
                             + "  HR=0x" + ex.HResult.ToString("X8") + "  " + ex.Message);
            }
        }

        internal static string DiagForTest(StartItem it)
        {
            StringBuilder b = new StringBuilder();
            string path = ApprovedPath(it);
            string n = ApprovedName(it);
            b.AppendLine("           --- 注册表诊断 ---");
            b.AppendLine("           位数=" + (Environment.Is64BitProcess ? "64" : "32")
                         + "  管理员=" + Trimmer.IsAdmin
                         + "  用户=" + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            b.AppendLine("           键=" + path + "   值名=" + n + "   IsHkcu=" + IsHkcu(it));

            DiagRun(b, "A 只读打开    ", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(path)) { return k == null ? "null（键不存在）" : "OK"; }
            });
            DiagRun(b, "B 可写打开    ", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(path, true)) { return k == null ? "null（打不开可写）" : "OK"; }
            });
            DiagRun(b, "C CreateSubKey", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.CreateSubKey(path)) { return k == null ? "null" : "OK"; }
            });
            DiagRun(b, "D OpenBaseKey+Create", delegate
            {
                using (RegistryKey r = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
                using (RegistryKey k = r.CreateSubKey(path)) { return k == null ? "null" : "OK"; }
            });
            DiagRun(b, "E 写同值(不改状态)", delegate
            {
                using (RegistryKey r = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
                using (RegistryKey k = r.OpenSubKey(path, true))
                {
                    if (k == null) return "打不开可写";
                    byte[] old = k.GetValue(n) as byte[];
                    if (old == null) return "该值名不存在（= 启用），跳过写入";
                    k.SetValue(n, old, RegistryValueKind.Binary);
                    byte[] nb = k.GetValue(n) as byte[];
                    return "OK（原值 " + old[0] + " → " + (nb == null ? "null" : nb[0].ToString()) + "）";
                }
            });
            DiagRun(b, "F 写临时值再删", delegate
            {
                using (RegistryKey r = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
                using (RegistryKey k = r.OpenSubKey(path, true))
                {
                    if (k == null) return "打不开可写";
                    k.SetValue("DSH_Diag", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);
                    k.DeleteValue("DSH_Diag", false);
                    return "OK";
                }
            });

            // 下面几项用来判断「是整个 HKCU 都不能写，还是只有这一个键不能写」。
            DiagRun(b, "G 写 Software  ", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey("Software", true)) { return k == null ? "null" : "OK"; }
            });
            DiagRun(b, "H 写 Explorer  ", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer", true)) { return k == null ? "null" : "OK"; }
            });
            DiagRun(b, "I 写 Run 键    ", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true)) { return k == null ? "null" : "OK"; }
            });
            DiagRun(b, "J 建临时键再删 ", delegate
            {
                using (RegistryKey k = Registry.CurrentUser.CreateSubKey("Software\\DSH_DiagTemp"))
                {
                    if (k == null) return "null";
                }
                Registry.CurrentUser.DeleteSubKey("Software\\DSH_DiagTemp", false);
                return "OK";
            });
            DiagRun(b, "K 原始 API     ", delegate
            {
                IntPtr h;
                int rc = RegOpenKeyExW(new IntPtr(0x80000001), path, 0, 0x0002, out h);   // HKCU, KEY_SET_VALUE
                if (rc == 0) CloseHandle(h);
                return "RegOpenKeyEx(KEY_SET_VALUE) 返回 " + rc + (rc == 5 ? " = 拒绝访问" : rc == 0 ? " = 成功" : "");
            });
            DiagRun(b, "L 进程令牌     ", delegate
            {
                System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent();
                return "受限=" + IsTokenRestricted(id.Token)
                       + "  完整性=" + IntegrityOf(id.Token)
                       + "  Is64Bit=" + Environment.Is64BitProcess;
            });
            return b.ToString();
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyExW(IntPtr hKey, string subKey, int options, int samDesired, out IntPtr result);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool IsTokenRestricted(IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int retLen);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);

        // 当前进程的完整性级别（界面/自检里显示，方便用户判断「是不是权限不够」）。
        internal static string CurrentIntegrity()
        {
            try
            {
                System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent();
                return IntegrityOf(id.Token);
            }
            catch { return "?"; }
        }

        private static string IntegrityOf(IntPtr token)
        {
            try
            {
                IntPtr p = Marshal.AllocHGlobal(64);
                try
                {
                    int len;
                    if (!GetTokenInformation(token, 25, p, 64, out len)) return "?";
                    IntPtr sid = Marshal.ReadIntPtr(p);
                    int rid = Marshal.ReadInt32(sid, 8 + Marshal.ReadByte(sid, 1) * 4 - 4);
                    // 完整性级别 RID：0x1000=低 0x2000=中 0x3000=高 0x4000=系统
                    // （以前把 0x2000 也显示成「低」，是判读写错了，容易误导排查。）
                    return rid >= 0x4000 ? "系统(" + rid + ")"
                         : rid >= 0x3000 ? "高(" + rid + ")"
                         : rid >= 0x2000 ? "中(" + rid + ")"
                         : "低(" + rid + ")";
                }
                finally { Marshal.FreeHGlobal(p); }
            }
            catch { return "?"; }
        }

        // ---------- 结束进程 ----------
        // 系统组件一律不碰：误杀 explorer / csrss 之类会把桌面搞崩，
        // 而用户想「关掉」的从来不是这些。
        internal static readonly string[] NeverKill = new string[] {
            "System", "Idle", "Registry", "Memory Compression", "csrss", "wininit", "winlogon",
            "services", "lsass", "smss", "dwm", "audiodg", "fontdrvhost", "Secure System", "LsaIso",
            "explorer", "sihost", "taskhostw", "RuntimeBroker", "ShellExperienceHost",
            "StartMenuExperienceHost", "SearchIndexer", "SearchApp", "ctfmon", "WmiPrvSE",
            "svchost", "spoolsv", "dllhost", "conhost", "SystemSettings", "ApplicationFrameHost",
            "SmoothWinTray"
        };

        public static string Kill(StartItem it)
        {
            if (string.IsNullOrEmpty(it.Exe)) return "这一项里没有可执行文件名，无法结束进程。";
            if (Trimmer.InList(NeverKill, it.Exe)) return "「" + it.Exe + "」是系统组件，程序不会去结束它。";
            int n = 0; long mb = 0; string err = "";
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    if (!string.Equals(p.ProcessName, it.Exe, StringComparison.OrdinalIgnoreCase)) continue;
                    mb += p.WorkingSet64 / 1048576;
                    p.Kill();
                    n++;
                }
                catch (Exception ex) { err = ex.Message; }
                finally { p.Dispose(); }
            }
            if (n == 0) return "没有找到正在运行的「" + it.Exe + "」（可能已经退出了）。";
            return "已结束 " + n + " 个「" + it.Exe + "」进程，释放约 " + mb + " MB 内存。"
                 + (err.Length > 0 ? "  （有进程没杀成功: " + err + "）" : "");
        }

        // 在资源管理器里定位这一项：.lnk 直接选中它，注册表项则去选它的 exe
        public static string OpenLocation(StartItem it)
        {
            try
            {
                string path = it.Cmd;
                if (!(it.Source == "StartupFolder" || it.Source == "CommonStartupFolder"))
                {
                    string s = it.Cmd.Trim();
                    if (s.StartsWith("\"")) { int e = s.IndexOf('"', 1); if (e > 1) s = s.Substring(1, e - 1); }
                    else { int sp = s.IndexOf(' '); if (sp > 0) s = s.Substring(0, sp); }
                    path = s;
                }
                if (File.Exists(path))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + path + "\"") { UseShellExecute = true });
                    return "";
                }
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", "\"" + dir + "\"") { UseShellExecute = true });
                    return "";
                }
                return "找不到这个文件了：\n" + path;
            }
            catch (Exception ex) { return "打开位置失败: " + ex.Message; }
        }

        public static string Text()
        {
            StringBuilder b = new StringBuilder();
            List<StartItem> list = Scan();

            int running = 0, off = 0;
            long total = 0;
            foreach (StartItem it in list)
            {
                if (it.RunningMB > 0) { running++; total += it.RunningMB; }
                if (!IsEnabled(it)) off++;
            }

            b.Append("开机自启项共 ").Append(list.Count).Append(" 个，其中 ").Append(running)
             .Append(" 个正在运行，合计占用 ").Append(total).Append(" MB 内存。")
             .Append(off > 0 ? "（另有 " + off + " 项已被禁用）" : "").AppendLine();
            b.AppendLine();
            b.AppendLine("这些东西开机就会自己起来，一直占着内存和 CPU。");
            b.AppendLine("想减少常驻负载，从这里挑「你其实用不上」的关掉最有效。");
            b.AppendLine();
            b.AppendLine("--- 按占用从大到小 ---");
            foreach (StartItem it in list)
            {
                b.Append(it.RunningMB >= 0 ? "[运行中 " + it.RunningMB + " MB] " : "[未运行] ");
                if (!IsEnabled(it)) b.Append("[已禁用] ");
                b.Append(it.Name).Append("   （").Append(it.Where).Append("）").AppendLine();
                b.Append("    ").Append(it.Cmd).AppendLine();
            }
            b.AppendLine();
            b.AppendLine("--- 怎么关 ---");
            b.AppendLine("1. 按 Ctrl+Shift+Esc 打开任务管理器 →「启动」选项卡 → 右键某项 →「禁用」");
            b.AppendLine("2. 或者：设置 → 应用 → 启动");
            b.AppendLine("3. 禁用只是不再自动启动，程序本身没删，随时能手动打开");
            b.AppendLine();
            b.AppendLine("建议保留：远程控制类（向日葵 / RustDesk / UU远程）、安全软件、显卡相关。");
            b.AppendLine("可以先关：各种更新器、助手、输入法扩展、游戏平台、下载工具。");
            return b.ToString();
        }
    }

    // ==================== 后台应用（独立窗口：进程树 / 启动时间 / 占用 / 可结束） ====================
    // 用户要的是把「后台应用」从自启项里拆出来单独看：
    //   · 每个程序下面挂出它的子进程（node 开 34 个、每个 dev server 一个）；
    //   · 每个进程什么时候启动的、已经跑了多久、占多大内存；
    //   · 想关哪个就关哪个，而且关的是「这一个进程」，不是「同名全杀」。
    // 这里刻意不做任何自动动作：只看，只在你点的时候才动手。
    internal class AppNode
    {
        public int Pid;
        public int ParentPid;
        public string Name = "";
        public string Path = "";
        public long MB;
        public DateTime Start = DateTime.MinValue;
        public long CpuMs;
        public double DiskMB;
        public int Threads;
        public IntPtr Hwnd = IntPtr.Zero;
        public bool HasWindow;
        public bool IsSelf;
        public List<AppNode> Kids = new List<AppNode>();
        public AppNode Parent;
        public AppNode Root;

        public long TotalMB
        {
            get
            {
                long m = MB;
                foreach (AppNode k in Kids) m += k.TotalMB;
                return m;
            }
        }

        public int Count
        {
            get
            {
                int n = 1;
                foreach (AppNode k in Kids) n += k.Count;
                return n;
            }
        }
    }

    internal static class AppScan
    {
        // 进程名 → 一句「它是干什么的」。只写确定的东西，认不出来就留空。
        internal static string Describe(string name)
        {
            switch (name.ToLowerInvariant())
            {
                case "node": return "Node.js（开发服务器 / 构建进程）";
                case "chrome": return "Chrome 浏览器（每个标签页一个进程）";
                case "msedge": return "Edge 浏览器（每个标签页一个进程）";
                case "firefox": return "Firefox 浏览器";
                case "weixin": return "微信";
                case "wechat": return "微信";
                case "qq": return "QQ";
                case "qqnt": return "QQ";
                case "wxwork": return "企业微信";
                case "code": return "VS Code";
                case "devenv": return "Visual Studio";
                case "docker desktop": return "Docker Desktop";
                case "com.docker.backend": return "Docker 后台引擎";
                case "explorer": return "Windows 桌面 / 文件管理器";
                case "svchost": return "Windows 服务宿主（一个进程里跑好几个系统服务）";
                case "dllhost": return "COM 代理（很多软件的组件跑在这里）";
                case "runtimebroker": return "UWP 应用代理";
                case "searchindexer": return "Windows 搜索索引";
                case "msmpeng": return "Microsoft Defender 杀毒引擎";
                case "qemu-system-x86_64": return "QEMU 虚拟机";
                case "java": return "Java 虚拟机";
                case "python": return "Python";
                case "pythonw": return "Python";
                case "dotnet": return ".NET 运行时宿主";
                case "msbuild": return "MSBuild 编译进程";
                case "git": return "Git";
                case "conhost": return "控制台窗口宿主";
                case "taskhostw": return "Windows 任务宿主";
                case "dwm": return "桌面窗口管理器（合成器）";
                case "ctfmon": return "输入法 / 文字服务";
                default: return "";
            }
        }

        internal static string Mb(long mb)
        {
            if (mb >= 10240) return (mb / 1024.0).ToString("0.0") + " GB";
            return mb + " MB";
        }

        internal static string Dur(TimeSpan t)
        {
            if (t.TotalSeconds < 0) return "未知";
            if (t.TotalDays >= 1) return (int)t.TotalDays + " 天 " + t.Hours + " 小时";
            if (t.TotalHours >= 1) return (int)t.TotalHours + " 小时 " + t.Minutes + " 分";
            if (t.TotalMinutes >= 1) return (int)t.TotalMinutes + " 分 " + t.Seconds + " 秒";
            return (int)t.TotalSeconds + " 秒";
        }

        // 一个进程已经跑了多久。启动时间读不到时（系统进程）要老实说读不到，
        // 不能拿 MinValue 去减 DateTime.Now，那会算出「739896 天」这种假数字。
        internal static string Age(AppNode n)
        {
            if (n == null || n.Start == DateTime.MinValue) return "读不到";
            return Dur(DateTime.Now - n.Start);
        }

        // 扫一遍所有进程，建成「顶层程序 → 子进程」的树。
        // 父进程只用一次 Toolhelp32 快照拿，不按进程逐个枚举（421 个进程那样会卡死）。
        internal static List<AppNode> Take(out string note)
        {
            note = "";
            Dictionary<int, AppNode> byId = new Dictionary<int, AppNode>();
            Dictionary<int, IntPtr> wins = Native.TopWindows();
            int selfPid = Process.GetCurrentProcess().Id;
            int noAccess = 0;

            Dictionary<int, int> ppid = new Dictionary<int, int>();
            Dictionary<int, int> thrd = new Dictionary<int, int>();
            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
            if (snap != IntPtr.Zero && snap != Native.INVALID_HANDLE_VALUE)
            {
                try
                {
                    Native.PROCESSENTRY32 pe = new Native.PROCESSENTRY32();
                    pe.dwSize = (uint)Marshal.SizeOf(typeof(Native.PROCESSENTRY32));
                    if (Native.Process32FirstW(snap, ref pe))
                    {
                        do
                        {
                            ppid[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID;
                            thrd[(int)pe.th32ProcessID] = (int)pe.cntThreads;
                        } while (Native.Process32NextW(snap, ref pe));
                    }
                }
                catch { }
                finally { Native.CloseHandle(snap); }
            }

            foreach (Process p in Process.GetProcesses())
            {
                IntPtr h = IntPtr.Zero;
                try
                {
                    AppNode n = new AppNode();
                    n.Pid = p.Id;
                    n.Name = p.ProcessName;
                    n.IsSelf = (p.Id == selfPid);
                    n.Threads = thrd.ContainsKey(p.Id) ? thrd[p.Id] : 0;
                    n.ParentPid = ppid.ContainsKey(p.Id) ? ppid[p.Id] : 0;
                    try { n.MB = p.WorkingSet64 / 1048576; } catch { n.MB = 0; }

                    h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
                    if (h != IntPtr.Zero)
                    {
                        long create, exit, kernel, user;
                        if (Native.GetProcessTimes(h, out create, out exit, out kernel, out user))
                        {
                            n.CpuMs = (kernel + user) / 10000;      // 100 纳秒 → 毫秒
                            // 系统进程（System / wininit / csrss 这些）读出来 create 是 0，
                            // FromFileTime(0) = 1601-01-01，减出来就是七十多万天。必须挡住。
                            if (create > 0)
                            {
                                try
                                {
                                    DateTime st = DateTime.FromFileTime(create);
                                    if (st.Year >= 2000 && st <= DateTime.Now) n.Start = st;
                                }
                                catch { }
                            }
                        }
                        Native.IO_COUNTERS io;
                        if (Native.GetProcessIoCounters(h, out io))
                            n.DiskMB = (io.ReadTransferCount + io.WriteTransferCount) / 1048576.0;
                        n.Path = Native.ProcessPathOf(h);
                    }
                    else noAccess++;

                    IntPtr w;
                    if (wins.TryGetValue(p.Id, out w)) { n.Hwnd = w; n.HasWindow = true; }
                    byId[p.Id] = n;
                }
                catch { }
                finally { if (h != IntPtr.Zero) Native.CloseHandle(h); try { p.Dispose(); } catch { } }
            }

            List<AppNode> all = new List<AppNode>(byId.Values);
            foreach (AppNode n in all)
            {
                if (n.ParentPid <= 0 || n.ParentPid == n.Pid) continue;
                AppNode par;
                if (!byId.TryGetValue(n.ParentPid, out par)) continue;
                // 防环：PID 被回收后父进程可能指向自己的后代，那样递归会栈溢出
                bool cyc = false;
                AppNode t = par;
                for (int i = 0; i < 64 && t != null; i++)
                {
                    if (t == n) { cyc = true; break; }
                    t = t.Parent;
                }
                if (cyc) continue;
                n.Parent = par;
                par.Kids.Add(n);
            }

            List<AppNode> roots = new List<AppNode>();
            foreach (AppNode n in all) if (n.Parent == null) roots.Add(n);
            foreach (AppNode r in roots) SetRoot(r, r);
            foreach (AppNode r in roots) SortTree(r);
            roots.Sort(delegate (AppNode a, AppNode b) { return b.TotalMB.CompareTo(a.TotalMB); });

            if (noAccess > 0) note = noAccess + " 个进程的详情读不到（权限不够，属正常现象）";
            return roots;
        }

        private static void SetRoot(AppNode n, AppNode r)
        {
            n.Root = r;
            foreach (AppNode k in n.Kids) SetRoot(k, r);
        }

        private static void SortTree(AppNode n)
        {
            n.Kids.Sort(delegate (AppNode a, AppNode b) { return b.TotalMB.CompareTo(a.TotalMB); });
            foreach (AppNode k in n.Kids) SortTree(k);
        }

        // 排序方式：内存（默认）/ CPU 累计 / 名字 / 启动时间
        internal const int SortMem = 0;
        internal const int SortCpu = 1;
        internal const int SortName = 2;
        internal const int SortStart = 3;

        internal static int CompareBy(AppNode a, AppNode b, int mode)
        {
            switch (mode)
            {
                case SortCpu:
                    return b.CpuMs.CompareTo(a.CpuMs);
                case SortName:
                    return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                case SortStart:
                    // 后起来的排前面 —— 刚冒出来的进程才是「谁又跑起来了」的答案。
                    // 读不到启动时间的（系统进程）一律沉到最后，不能拿 MinValue 当排序键。
                    long ta = (a.Start == DateTime.MinValue ? long.MinValue : a.Start.Ticks);
                    long tb = (b.Start == DateTime.MinValue ? long.MinValue : b.Start.Ticks);
                    return tb.CompareTo(ta);
                default:
                    return b.TotalMB.CompareTo(a.TotalMB);
            }
        }

        internal static void SortAll(List<AppNode> roots, int mode)
        {
            roots.Sort(delegate (AppNode a, AppNode b) { return CompareBy(a, b, mode); });
            foreach (AppNode r in roots) SortTree(r, mode);
        }

        internal static void SortTree(AppNode n, int mode)
        {
            n.Kids.Sort(delegate (AppNode a, AppNode b) { return CompareBy(a, b, mode); });
            foreach (AppNode k in n.Kids) SortTree(k, mode);
        }

        // 整棵树一共占了多少内存（用户最关心的那一个数）
        internal static long TotalOf(List<AppNode> roots)
        {
            long mb = 0;
            foreach (AppNode r in roots) mb += r.TotalMB;
            return mb;
        }

        // 收集一棵子树里的全部进程（含自己）
        internal static void Collect(AppNode n, List<AppNode> into)
        {
            into.Add(n);
            foreach (AppNode k in n.Kids) Collect(k, into);
        }

        internal static string RootText(AppNode r)
        {
            if (r.Kids.Count == 0)
                return r.Name + "   ·   " + Mb(r.MB) + "   ·   pid " + r.Pid + "   ·   " + Age(r);
            return r.Name + "   ·   合计 " + Mb(r.TotalMB) + "   ·   " + r.Count + " 个进程   ·   " + Age(r);
        }

        internal static string KidText(AppNode n)
        {
            return n.Name + "   ·   " + Mb(n.MB) + "   ·   pid " + n.Pid + "   ·   " + Age(n);
        }

        // 结束「这一个」进程（按 PID，不是按名字全杀）
        internal static string KillPid(int pid)
        {
            if (pid <= 0) return "没有选中任何进程。";
            if (pid == Process.GetCurrentProcess().Id) return "这是 SmoothWin 自己，不能关。";
            Process p = null;
            try
            {
                p = Process.GetProcessById(pid);
                string n = p.ProcessName;
                if (Trimmer.InList(Startup.NeverKill, n))
                    return "「" + n + "」是系统组件，程序不会去结束它。";
                long mb = 0;
                try { mb = p.WorkingSet64 / 1048576; } catch { }
                p.Kill();
                return "已结束「" + n + "」(pid " + pid + ")，释放约 " + mb + " MB 内存。";
            }
            catch (ArgumentException) { return "这个进程已经不在了（可能自己退出了）。"; }
            catch (Exception ex)
            {
                return "结束失败：" + ex.Message + "。如果提示拒绝访问，点左下角「以管理员身份重新打开」再试。";
            }
            finally { if (p != null) { try { p.Dispose(); } catch { } } }
        }

        // 结束「一组」：顶层程序 + 它下面全部子进程
        internal static string KillGroup(AppNode root)
        {
            List<AppNode> all = new List<AppNode>();
            Collect(root, all);
            int ok = 0, skip = 0;
            long mb = 0;
            string err = "";
            int selfPid = Process.GetCurrentProcess().Id;
            foreach (AppNode n in all)
            {
                if (n.Pid == selfPid || Trimmer.InList(Startup.NeverKill, n.Name)) { skip++; continue; }
                Process p = null;
                try
                {
                    p = Process.GetProcessById(n.Pid);
                    mb += n.MB;
                    p.Kill();
                    ok++;
                }
                catch (ArgumentException) { }
                catch (Exception ex) { err = ex.Message; }
                finally { if (p != null) { try { p.Dispose(); } catch { } } }
            }
            StringBuilder b = new StringBuilder();
            b.Append("已结束 ").Append(ok).Append(" 个进程，释放约 ").Append(mb).Append(" MB 内存。");
            if (skip > 0) b.Append("  跳过 ").Append(skip).Append(" 个（系统组件或本程序自己）。");
            if (err.Length > 0) b.Append("  有进程没能结束：").Append(err);
            return b.ToString();
        }
    }

    // ==================== 后台应用窗口 ====================
    // 自启项回答「开机时谁自己起来了」，这个窗口回答「现在谁在跑、谁在占内存、谁又生了孩子」。
    // 两者拆开：自启项那张表是注册表里的静态清单，这里的树是此刻内存里的活进程。
    internal class AppForm : Form
    {
        private TrayApp app;
        private TreeView tv;
        private Label lHead, lHint;
        private TextBox tbFind, box;
        private Button bKill, bKillAll, bCloseWin, bFront, bOpen, bRefresh, bCopy, bExport, bStartup, bClose;
        private CheckBox cbBig, cbAuto;
        private System.Windows.Forms.Timer tAuto;
        private System.Windows.Forms.Timer tFind;
        private ComboBox cbSort;
        private ContextMenuStrip menu;
        private List<AppNode> roots = new List<AppNode>();
        private string scanNote = "";
        private int sortMode = AppScan.SortMem;
        private long lastTotalMB;

        public AppForm(TrayApp owner)
        {
            app = owner;
            Text = "SmoothWin 后台应用";
            ClientSize = new Size(940, 620);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            MaximizeBox = true;
            ShowInTaskbar = true;
            Font = new Font("Microsoft YaHei UI", 9f);
            BackColor = Color.FromArgb(244, 246, 249);

            int W = ClientSize.Width, H = ClientSize.Height;

            lHead = new Label();
            lHead.AutoSize = false;
            lHead.SetBounds(12, 10, W - 24, 20);
            lHead.Font = new Font("Microsoft YaHei UI", 10.5f, FontStyle.Bold);
            lHead.Text = "现在在跑的后台应用";
            Controls.Add(lHead);

            lHint = new Label();
            lHint.AutoSize = false;
            lHint.SetBounds(12, 32, W - 24, 18);
            lHint.ForeColor = Color.FromArgb(122, 128, 138);
            lHint.Text = "只在这里看，不选中就不动任何东西。左边点一行，右边就是它的全部信息；带加号的行说明它下面还有子进程。右键那一行有更多操作。";
            Controls.Add(lHint);

            Label lFind = new Label();
            lFind.AutoSize = false;
            lFind.SetBounds(12, 60, 42, 22);
            lFind.Text = "筛选:";
            Controls.Add(lFind);

            tbFind = new TextBox();
            tbFind.SetBounds(56, 57, 240, 24);
            tbFind.TextChanged += delegate { tFind.Stop(); tFind.Start(); };
            Controls.Add(tbFind);

            cbBig = new CheckBox();
            cbBig.AutoSize = true;
            cbBig.SetBounds(306, 58, 190, 22);
            cbBig.Text = "只看占内存 100 MB 以上";
            cbBig.CheckedChanged += delegate { Reload(); };
            Controls.Add(cbBig);

            cbAuto = new CheckBox();
            cbAuto.AutoSize = true;
            cbAuto.SetBounds(506, 58, 150, 22);
            cbAuto.Text = "每 5 秒自动刷新";
            Controls.Add(cbAuto);

            Label lSort = new Label();
            lSort.AutoSize = false;
            lSort.SetBounds(668, 60, 42, 22);
            lSort.Text = "排序:";
            Controls.Add(lSort);

            cbSort = new ComboBox();
            cbSort.DropDownStyle = ComboBoxStyle.DropDownList;
            cbSort.SetBounds(710, 57, 150, 24);
            cbSort.Items.Add("占内存最多");
            cbSort.Items.Add("CPU 用得最多");
            cbSort.Items.Add("按名字");
            cbSort.Items.Add("最近才启动的");
            cbSort.SelectedIndex = 0;
            cbSort.SelectedIndexChanged += delegate
            {
                if (cbSort.SelectedIndex >= 0) sortMode = cbSort.SelectedIndex;
                Reload();
            };
            Controls.Add(cbSort);

            tv = new TreeView();
            tv.SetBounds(12, 88, 600, H - 178);
            tv.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            tv.CheckBoxes = true;
            tv.HideSelection = false;
            tv.FullRowSelect = true;
            tv.ShowLines = true;
            tv.ShowRootLines = true;
            tv.ItemHeight = 22;
            tv.BackColor = Color.White;
            tv.AfterSelect += delegate { OnSelect(); };
            tv.NodeMouseDoubleClick += delegate { OpenLocation(); };
            // 右键必须先让这一行变成选中行。TreeView 默认右键不改选中项，
            // 那样会变成「看着点 A、实际关掉上一次选的 B」—— 杀进程的按钮上这不能忍。
            tv.NodeMouseClick += delegate (object s, TreeNodeMouseClickEventArgs e)
            {
                if (e.Button == MouseButtons.Right && e.Node != null) tv.SelectedNode = e.Node;
            };
            tv.AfterCheck += delegate (object s, TreeViewEventArgs e)
            {
                // 勾父节点 = 连同它下面的子进程一起勾/去勾
                if (e.Node == null) return;
                SetKidsChecked(e.Node, e.Node.Checked);
            };
            Controls.Add(tv);

            box = new TextBox();
            box.Multiline = true;
            box.ReadOnly = true;
            box.ScrollBars = ScrollBars.Vertical;
            box.WordWrap = true;
            box.Font = new Font("Microsoft YaHei UI", 9f);
            box.BackColor = Color.FromArgb(250, 251, 253);
            box.BorderStyle = BorderStyle.FixedSingle;
            box.TabStop = false;
            box.HideSelection = true;
            box.SetBounds(620, 88, W - 632, H - 178);
            box.Anchor = AnchorStyles.Top | AnchorStyles.Right | AnchorStyles.Bottom;
            box.Text = "左边选一个进程，这里会显示它的启动时间、已经跑了多久、占多大内存、磁盘读写了多少。";
            Controls.Add(box);

            // 右键菜单：树上的常用动作，省得每次把鼠标拖到底下的按钮条。
            menu = new ContextMenuStrip();
            menu.Items.Add("切到前台", null, delegate { BringFront(); });
            menu.Items.Add("关闭窗口（先让它自己保存）", null, delegate { CloseWin(); });
            menu.Items.Add("打开所在位置", null, delegate { OpenLocation(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("结束这个进程", null, delegate { KillSel(); });
            menu.Items.Add("结束整个程序组", null, delegate { KillGroupSel(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("复制这一行的信息", null, delegate { CopyOne(); });
            menu.Opening += delegate (object s, System.ComponentModel.CancelEventArgs e)
            {
                AppNode n = Selected();
                bool has = n != null;
                bool sys = has && Trimmer.InList(Startup.NeverKill, n.Name);
                menu.Items[0].Enabled = has && n.HasWindow;
                menu.Items[1].Enabled = has && n.HasWindow;
                menu.Items[2].Enabled = has && n.Path.Length > 0;
                menu.Items[4].Enabled = has && !sys && !n.IsSelf;
                menu.Items[5].Enabled = has && !sys && !n.IsSelf;
                menu.Items[7].Enabled = has;
            };
            tv.ContextMenuStrip = menu;

            tFind = new System.Windows.Forms.Timer();
            tFind.Interval = 400;
            tFind.Tick += delegate { tFind.Stop(); Reload(); };

            // 自动刷新只在窗口看得见的时候扫，窗口一关就停 —— 后台每秒枚举 400 个进程是纯浪费。
            tAuto = new System.Windows.Forms.Timer();
            tAuto.Interval = 5000;
            tAuto.Tick += delegate { if (cbAuto.Checked && Visible) Reload(); };
            tAuto.Start();

            FormClosed += delegate { tAuto.Stop(); tFind.Stop(); };

            int by1 = H - 76, by2 = H - 42;
            bKill = MkBtn("结束这个进程", 12, by1, 130, false);
            bKill.Click += delegate { KillSel(); };
            bKillAll = MkBtn("结束整个程序组", 148, by1, 140, false);
            bKillAll.Click += delegate { KillGroupSel(); };
            bCloseWin = MkBtn("关闭窗口", 294, by1, 100, false);
            bCloseWin.Click += delegate { CloseWin(); };
            bFront = MkBtn("切到前台", 400, by1, 100, false);
            bFront.Click += delegate { BringFront(); };
            bOpen = MkBtn("打开所在位置", 506, by1, 120, false);
            bOpen.Click += delegate { OpenLocation(); };
            bRefresh = MkBtn("刷新", 12, by2, 80, false);
            bRefresh.Click += delegate { Reload(); };
            bCopy = MkBtn("复制清单", 98, by2, 100, false);
            bCopy.Click += delegate { CopyList(); };
            bExport = MkBtn("导出清单…", 204, by2, 110, false);
            bExport.Click += delegate { ExportList(); };
            bStartup = MkBtn("开机自启项", 320, by2, 110, false);
            bStartup.Click += delegate { app.ShowStartup(); };
            bClose = MkBtn("关闭", W - 112, by2, 100, true);
            bClose.Click += delegate { Close(); };

            Reload();
        }

        private Button MkBtn(string text, int x, int y, int w, bool rightAnchor)
        {
            Button b = new Button();
            b.Text = text;
            b.SetBounds(x, y, w, 30);
            b.FlatStyle = FlatStyle.System;
            b.Anchor = rightAnchor ? (AnchorStyles.Right | AnchorStyles.Bottom) : (AnchorStyles.Left | AnchorStyles.Bottom);
            Controls.Add(b);
            return b;
        }

        private static void SetKidsChecked(TreeNode n, bool on)
        {
            foreach (TreeNode c in n.Nodes) { c.Checked = on; SetKidsChecked(c, on); }
        }

        private void Reload()
        {
            try
            {
                string note;
                List<AppNode> list = AppScan.Take(out note);
                AppScan.SortAll(list, sortMode);   // 用户选的排序方式
                roots = list;
                scanNote = note;
                lastTotalMB = AppScan.TotalOf(list);
                string f = (tbFind.Text == null ? "" : tbFind.Text.Trim());
                tv.BeginUpdate();
                tv.Nodes.Clear();
                int shown = 0;
                foreach (AppNode r in list)
                {
                    if (!Keep(r, f)) continue;
                    TreeNode tn = new TreeNode(AppScan.RootText(r));
                    tn.Tag = r;
                    tn.Checked = r.Kids.Count > 0;
                    AddKids(tn, r, f);
                    tv.Nodes.Add(tn);
                    shown++;
                    // 有子进程、又不是小角色的，默认展开 —— 用户要看的正是「谁生了谁」
                    if (r.Kids.Count > 0 && r.TotalMB >= 50) tn.Expand();
                }
                tv.EndUpdate();
                lHead.Text = "现在在跑的后台应用：共 " + list.Count + " 个顶层程序"
                    + (f.Length > 0 ? "（筛选后显示 " + shown + " 个）" : "")
                    + "   ·   全部合计 " + AppScan.Mb(lastTotalMB)
                    + (scanNote.Length > 0 ? "   ·   " + scanNote : "");
                OnSelect();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "读取进程失败：" + ex.Message, "后台应用",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static bool Match(AppNode n, string f)
        {
            if (n.Name.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            foreach (AppNode k in n.Kids) if (Match(k, f)) return true;
            return false;
        }

        private bool Keep(AppNode n, string f)
        {
            // 文字筛选：名字对得上就留；对不上但它的子进程对得上，也留（不然看不到「谁生的它」）。
            if (f.Length > 0 && !Match(n, f)) return false;
            // 大占用筛选：自己小但下面挂着大进程的，同样要留 —— 那才是真正吃内存的那一层。
            if (cbBig.Checked && n.TotalMB < 100) return false;
            return true;
        }

        private void AddKids(TreeNode tn, AppNode n, string f)
        {
            foreach (AppNode k in n.Kids)
            {
                if (!Keep(k, f)) continue;
                TreeNode c = new TreeNode(AppScan.KidText(k));
                c.Tag = k;
                c.Checked = k.Kids.Count > 0;
                AddKids(c, k, f);
                tn.Nodes.Add(c);
            }
        }

        private AppNode Selected()
        {
            if (tv.SelectedNode == null) return null;
            return tv.SelectedNode.Tag as AppNode;
        }

        private bool NeedSelect()
        {
            if (Selected() != null) return true;
            MessageBox.Show(this, "先在左边点一个进程。", "后台应用",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }


        private void OnSelect()
        {
            AppNode n = Selected();
            if (n == null)
            {
                box.Text = "左边选一个进程，这里会显示它的启动时间、已经跑了多久、占多大内存、磁盘读写了多少。";
            }
            else
            {
                StringBuilder b = new StringBuilder();
                b.AppendLine("名称    : " + n.Name + (n.IsSelf ? "   <- 这就是 SmoothWin 自己" : ""));
                b.AppendLine("PID     : " + n.Pid);
                AppNode p = n.Parent;
                if (p != null) b.AppendLine("父进程  : " + p.Name + " (pid " + p.Pid + ")");
                else b.AppendLine("父进程  : 没有（它是最上层的程序，父进程已经不在了）");
                b.AppendLine("启动时间: " + (n.Start == DateTime.MinValue ? "读不到" : n.Start.ToString("yyyy-MM-dd HH:mm:ss")));
                b.AppendLine("已运行  : " + AppScan.Age(n));
                b.AppendLine("内存    : " + AppScan.Mb(n.MB)
                    + (n.Kids.Count > 0 ? "（连子进程一共 " + AppScan.Mb(n.TotalMB) + "）" : ""));
                b.AppendLine("CPU 累计: " + AppScan.Dur(TimeSpan.FromMilliseconds(n.CpuMs)));
                b.AppendLine("磁盘累计: " + (n.DiskMB >= 1024 ? (n.DiskMB / 1024.0).ToString("0.00") + " GB" : n.DiskMB.ToString("0.0") + " MB"));
                b.AppendLine("线程数  : " + n.Threads);
                b.AppendLine("窗口    : " + (n.HasWindow ? "有（可以「关闭窗口」或「切到前台」）" : "没有（它躲在后台跑）"));
                string d = AppScan.Describe(n.Name);
                if (d.Length > 0) b.AppendLine("这是啥  : " + d);
                b.AppendLine("子进程  : " + n.Kids.Count + " 个"
                    + (n.Kids.Count > 0 ? "（连它自己一共 " + n.Count + " 个）" : ""));
                if (n.Path.Length > 0)
                {
                    b.AppendLine();
                    b.AppendLine("程序位置:");
                    b.AppendLine(n.Path);
                }
                box.Text = b.ToString();
                box.SelectionStart = 0;
                box.SelectionLength = 0;
            }
            SyncButtons();
        }

        private void SyncButtons()
        {
            AppNode n = Selected();
            bool sys = n != null && Trimmer.InList(Startup.NeverKill, n.Name);
            bKill.Enabled = n != null && !sys && !n.IsSelf;
            bKillAll.Enabled = n != null && !sys && !n.IsSelf;
            bCloseWin.Enabled = n != null && n.HasWindow;
            bFront.Enabled = n != null && n.HasWindow;
            bOpen.Enabled = n != null && n.Path.Length > 0;
        }

        private void KillSel()
        {
            if (!NeedSelect()) return;
            AppNode n = Selected();
            string nl = Environment.NewLine + Environment.NewLine;
            string msg = "确定要结束「" + n.Name + "」(pid " + n.Pid + ") 吗？" + nl
                + "没有保存的工作会丢失。它下面还有 " + n.Kids.Count + " 个子进程，关这个不会连它们一起关。";
            if (MessageBox.Show(this, msg, "结束进程", MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string r = AppScan.KillPid(n.Pid);
            MessageBox.Show(this, r, "结束进程", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Reload();
        }

        private void KillGroupSel()
        {
            if (!NeedSelect()) return;
            AppNode n = Selected();
            AppNode r0 = (n.Root == null ? n : n.Root);
            if (r0.IsSelf)
            {
                MessageBox.Show(this, "这是 SmoothWin 自己，不能关。", "结束进程",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string nl = Environment.NewLine + Environment.NewLine;
            string msg = "确定要结束「" + r0.Name + "」以及它下面全部 " + (r0.Count - 1)
                + " 个子进程吗？" + nl + "一共 " + r0.Count + " 个进程，合计 " + AppScan.Mb(r0.TotalMB)
                + " 内存。没有保存的工作会丢失。";
            if (MessageBox.Show(this, msg, "结束整个程序组", MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string r = AppScan.KillGroup(r0);
            MessageBox.Show(this, r, "结束整个程序组", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Reload();
        }

        private void CloseWin()
        {
            if (!NeedSelect()) return;
            AppNode n = Selected();
            if (!n.HasWindow) return;
            // 发 WM_CLOSE：程序该弹「保存吗」的会自己弹，比直接杀进程安全。
            Native.PostMessageW(n.Hwnd, Native.WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
            System.Threading.Thread.Sleep(400);
            Reload();
        }

        private void BringFront()
        {
            if (!NeedSelect()) return;
            AppNode n = Selected();
            if (!n.HasWindow) return;
            try { Native.SetForegroundWindow(n.Hwnd); }
            catch { }
        }

        private void OpenLocation()
        {
            if (!NeedSelect()) return;
            AppNode n = Selected();
            string p = n.Path;
            if (p.Length == 0)
            {
                MessageBox.Show(this, "这一项取不到程序路径（多半是权限不够的进程）。", "打开所在位置",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try { Process.Start("explorer.exe", "/select,\"" + p + "\""); }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "打开所在位置",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void CopyList()
        {
            StringBuilder b = new StringBuilder();
            b.AppendLine("SmoothWin 后台应用清单  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            b.AppendLine();
            foreach (AppNode r in roots) DumpNode(b, r, 0);
            try
            {
                Clipboard.SetText(b.ToString());
                MessageBox.Show(this, "已复制到剪贴板。", "复制清单",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "复制清单",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // 只复制选中这一行的信息 —— 用户想贴给别人的往往就是一个进程，不是整份清单。
        private void CopyOne()
        {
            AppNode n = Selected();
            if (n == null) return;
            StringBuilder b = new StringBuilder();
            b.AppendLine("名称    : " + n.Name);
            b.AppendLine("PID     : " + n.Pid);
            b.AppendLine("内存    : " + AppScan.Mb(n.MB)
                + (n.Kids.Count > 0 ? "（连子进程一共 " + AppScan.Mb(n.TotalMB) + "，" + n.Count + " 个进程）" : ""));
            b.AppendLine("启动时间: " + (n.Start == DateTime.MinValue ? "读不到" : n.Start.ToString("yyyy-MM-dd HH:mm:ss")));
            b.AppendLine("已运行  : " + AppScan.Age(n));
            b.AppendLine("CPU 累计: " + AppScan.Dur(TimeSpan.FromMilliseconds(n.CpuMs)));
            b.AppendLine("磁盘累计: " + n.DiskMB.ToString("0.0") + " MB");
            if (n.Path.Length > 0) b.AppendLine("程序位置: " + n.Path);
            try
            {
                Clipboard.SetText(b.ToString());
                MessageBox.Show(this, "已复制这一行的信息。", "复制",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "复制",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void ExportList()
        {
            SaveFileDialog d = new SaveFileDialog();
            d.Title = "导出后台应用清单";
            d.Filter = "文本文件 (*.txt)|*.txt";
            d.FileName = "SmoothWin-后台应用-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".txt";
            if (d.ShowDialog(this) != DialogResult.OK) return;
            StringBuilder b = new StringBuilder();
            b.AppendLine("SmoothWin 后台应用清单  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            b.AppendLine("（缩进表示父子关系；同一行是：名字 pid= 内存 启动时间 已运行）");
            b.AppendLine();
            foreach (AppNode r in roots) DumpNode(b, r, 0);
            try
            {
                File.WriteAllText(d.FileName, b.ToString(), new UTF8Encoding(true));
                MessageBox.Show(this, "已导出到：" + d.FileName, "导出清单",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "导出清单",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void DumpNode(StringBuilder b, AppNode n, int depth)
        {
            b.Append(new string(' ', depth * 2));
            b.Append(n.Name).Append("  pid=").Append(n.Pid)
             .Append("  ").Append(AppScan.Mb(n.MB))
             .Append("  启动=").Append(n.Start == DateTime.MinValue ? "?" : n.Start.ToString("HH:mm:ss"))
             .Append("  已运行=").Append(AppScan.Age(n)).AppendLine();
            foreach (AppNode k in n.Kids) DumpNode(b, k, depth + 1);
        }

        // ---- 给命令行自检用 ----
        internal string DumpForTest()
        {
            StringBuilder b = new StringBuilder();
            b.AppendLine("标题        : " + Text);
            b.AppendLine("客户区      : " + ClientSize.Width + " x " + ClientSize.Height);
            b.AppendLine("管理员      : " + Trimmer.IsAdmin + "   进程完整性=" + Startup.CurrentIntegrity());
            b.AppendLine("顶层程序数  : " + roots.Count + (scanNote.Length > 0 ? "   (" + scanNote + ")" : ""));
            int nodes = 0, kids = 0;
            foreach (AppNode r in roots) { nodes += r.Count; if (r.Kids.Count > 0) kids++; }
            b.AppendLine("进程总数    : " + nodes + "   其中 " + kids + " 个顶层程序带子进程");
            b.AppendLine("树里的行数  : " + CountRows(tv.Nodes));
            b.AppendLine();
            b.AppendLine("--- 前 20 个顶层程序（名字 / 合计内存 / 进程数 / 跑了多久 / 子进程数）---");
            int i = 0;
            foreach (AppNode r in roots)
            {
                if (i++ >= 20) break;
                b.Append("  ").Append(i).Append(". ").Append(r.Name)
                 .Append("  ").Append(AppScan.Mb(r.TotalMB))
                 .Append("  ").Append(r.Count).Append(" 个进程")
                 .Append("  跑了 ").Append(AppScan.Age(r))
                 .Append("  子进程 ").Append(r.Kids.Count).AppendLine();
            }
            b.AppendLine();
            b.AppendLine("--- 按钮右边缘（都要 <= " + ClientSize.Width + "）---");
            foreach (Control c in Controls)
            {
                Button btn = c as Button;
                if (btn == null) continue;
                b.Append("  ").Append(btn.Text).Append(" 右边缘=").Append(btn.Right)
                 .Append(btn.Right <= ClientSize.Width ? "  OK" : "  出界了").AppendLine();
            }
            return b.ToString();
        }

        private static int CountRows(TreeNodeCollection ns)
        {
            int n = 0;
            foreach (TreeNode t in ns) n += 1 + CountRows(t.Nodes);
            return n;
        }

        // 真实地开一个子进程、在树里找到它、再按 PID 关掉它 —— 全程走用户点按钮时走的同一段代码。
        internal string SelfTestKill()
        {
            StringBuilder b = new StringBuilder();
            Process a = null, c = null;
            try
            {
                a = Process.Start("ping.exe", "-n 25 127.0.0.1");
                c = Process.Start("ping.exe", "-n 25 127.0.0.1");
                if (a == null || c == null) { b.AppendLine("起不来测试进程（ping.exe）。"); return b.ToString(); }
                System.Threading.Thread.Sleep(700);

                string note;
                List<AppNode> list = AppScan.Take(out note);
                int selfPid = Process.GetCurrentProcess().Id;
                // 注意：这里必须递归找整棵树。ping 挂在 SmoothWinTray 自己下面，
                // 而 SmoothWinTray 通常不是顶层（父进程是 explorer），只扫 list 永远找不到。
                AppNode self = FindPid(list, selfPid);
                AppNode ka = FindPid(list, a.Id);
                AppNode kc = FindPid(list, c.Id);
                b.AppendLine("测试子进程  : a=pid " + a.Id + "   c=pid " + c.Id);
                b.AppendLine("在树里找到  : a=" + (ka != null ? "找到了" : "没找到")
                    + "   c=" + (kc != null ? "找到了" : "没找到"));
                b.AppendLine("父进程认对了: a=" + (ka != null && ka.ParentPid == selfPid
                    ? "是（父进程就是本程序）"
                    : "否（父进程=" + (ka == null ? "?" : ka.ParentPid.ToString()) + "）"));
                if (self != null)
                {
                    bool inTree = false;
                    foreach (AppNode k in self.Kids) if (k.Pid == a.Id || k.Pid == c.Id) inTree = true;
                    b.AppendLine("挂在自程序下: " + (inTree ? "是（树里是本程序 -> ping 子进程）" : "否"));
                    b.AppendLine("自程序子进程: " + self.Kids.Count + " 个");
                }

                b.AppendLine();
                b.AppendLine("--- 关掉其中一个（按 PID）---");
                b.AppendLine("KillPid     : " + AppScan.KillPid(a.Id));
                System.Threading.Thread.Sleep(500);
                b.AppendLine("a 还在吗    : " + (Alive(a.Id) ? "还在（没关掉）" : "已经没了 OK"));
                b.AppendLine("c 还在吗    : " + (Alive(c.Id) ? "还在 OK（只关了 a，没有连坐）" : "也没了（不该）"));

                b.AppendLine();
                b.AppendLine("--- 关掉整组 ---");
                if (self != null)
                {
                    b.AppendLine("KillGroup   : " + AppScan.KillGroup(self));
                    System.Threading.Thread.Sleep(500);
                    b.AppendLine("c 还在吗    : " + (Alive(c.Id) ? "还在（没关掉）" : "已经没了 OK"));
                    b.AppendLine("本程序还在吗: " + (Alive(selfPid) ? "在 OK（自己不会被自己关掉）" : "没了（严重错误）"));
                }

                b.AppendLine();
                b.AppendLine("--- 系统进程保护 ---");
                b.AppendLine("关 explorer  : " + AppScan.KillPid(PidOf("explorer")));
                b.AppendLine("关 SmoothWin : " + AppScan.KillPid(selfPid));
            }
            catch (Exception ex) { b.AppendLine("自检出错: " + ex.Message); }
            finally
            {
                try { if (a != null && Alive(a.Id)) a.Kill(); }
                catch { }
                try { if (c != null && Alive(c.Id)) c.Kill(); }
                catch { }
                if (a != null) a.Dispose();
                if (c != null) c.Dispose();
            }
            return b.ToString();
        }

        // 在整棵树里按 PID 找一个节点（顶层 + 所有后代）
        private static AppNode FindPid(List<AppNode> roots, int pid)
        {
            foreach (AppNode r in roots)
            {
                AppNode hit = FindPidIn(r, pid);
                if (hit != null) return hit;
            }
            return null;
        }

        private static AppNode FindPidIn(AppNode n, int pid)
        {
            if (n == null) return null;
            if (n.Pid == pid) return n;
            foreach (AppNode k in n.Kids)
            {
                AppNode hit = FindPidIn(k, pid);
                if (hit != null) return hit;
            }
            return null;
        }

        // 自检新增的几样：排序真的生效了没有、右键菜单在不在、右键会不会先选中。
        internal string SelfTestExtras()
        {
            StringBuilder b = new StringBuilder();
            try
            {
                b.AppendLine("排序方式数  : " + cbSort.Items.Count + " 种（" + cbSort.Items[0] + " / " + cbSort.Items[1]
                    + " / " + cbSort.Items[2] + " / " + cbSort.Items[3] + "）");

                int[] modes = new int[] { AppScan.SortMem, AppScan.SortCpu, AppScan.SortName, AppScan.SortStart };
                string[] names = new string[] { "占内存最多", "CPU 用得最多", "按名字", "最近才启动的" };
                for (int i = 0; i < modes.Length; i++)
                {
                    cbSort.SelectedIndex = i;      // 走用户点下拉框时走的同一条路
                    Application.DoEvents();
                    bool ok = true;
                    string why = "";
                    for (int k = 1; k < roots.Count; k++)
                    {
                        int c = AppScan.CompareBy(roots[k - 1], roots[k], modes[i]);
                        if (c > 0) { ok = false; why = "第 " + k + " 和第 " + (k + 1) + " 个顺序反了"; break; }
                    }
                    b.AppendLine("排序 " + names[i] + "  : " + (ok ? "整棵树都是这个顺序 OK" : "没排对 —— " + why)
                        + "（第一个是 " + (roots.Count > 0 ? roots[0].Name : "无") + "）");
                }
                cbSort.SelectedIndex = 0;
                Application.DoEvents();

                b.AppendLine("右键菜单    : " + (menu == null ? "没有" : menu.Items.Count + " 项（" + menu.Items[0].Text + " / "
                    + menu.Items[4].Text + " / " + menu.Items[5].Text + "）"));
                b.AppendLine("树上挂了菜单: " + (tv.ContextMenuStrip == menu ? "是 OK" : "否（右键出不来）"));

                // 右键要先选中：模拟「右键点第二行」，看 Selected() 会不会跟着变。
                if (tv.Nodes.Count >= 2)
                {
                    tv.SelectedNode = tv.Nodes[0];
                    Application.DoEvents();
                    AppNode first = Selected();
                    tv.SelectedNode = tv.Nodes[1];
                    Application.DoEvents();
                    AppNode second = Selected();
                    b.AppendLine("右键前先选中: " + ((first != null && second != null && first.Pid != second.Pid)
                        ? "是 OK（换行后选中的 PID 跟着换了）" : "否（选中的还是同一个）"));
                }
                else b.AppendLine("右键前先选中: 树里行数不够，跳过");

                b.AppendLine("全部合计内存: " + AppScan.Mb(lastTotalMB));
                b.AppendLine("标题行      : " + lHead.Text);
            }
            catch (Exception ex) { b.AppendLine("扩展自检出错: " + ex.Message); }
            return b.ToString();
        }

        private static int PidOf(string name)
        {
            try
            {
                Process[] ps = Process.GetProcessesByName(name);
                if (ps.Length > 0)
                {
                    int id = ps[0].Id;
                    foreach (Process p in ps) p.Dispose();
                    return id;
                }
            }
            catch { }
            return 0;
        }

        private static bool Alive(int pid)
        {
            if (pid <= 0) return false;
            try
            {
                using (Process p = Process.GetProcessById(pid)) { return !p.HasExited; }
            }
            catch { return false; }
        }
    }

    // ==================== 开机自启项（可操作表格） ====================
    // 用户要的不是「再看一遍文本」，而是能动手：启用 / 禁用自启、结束正在跑的进程、跳到程序所在目录。
    // 实现上有一件事必须守住：禁用自启**不删 Run 键里的任何东西**，只在 Explorer 的
    // StartupApproved 下写一个二进制标记（任务管理器点「禁用」干的也是同一件事），
    // 所以随时能原样启用回来 —— 之前自动关自启把用户的远控软件弄没了的坑不能再踩。
    // 程序绝不自动改任何一项：每个动作都要用户自己点出来。
    internal class StartupForm : Form
    {
        private TrayApp app;
        private ListView lv;
        private Label lHead, lHint;
        private Button bToggle, bKill, bOpen, bRefresh, bClose;

        public StartupForm(TrayApp owner)
        {
            app = owner;
            Text = "SmoothWin 开机自启项";
            ClientSize = new Size(880, 520);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            MaximizeBox = true;
            ShowInTaskbar = false;
            Font = new Font("Microsoft YaHei UI", 9f);
            BackColor = Color.FromArgb(244, 246, 249);

            lHead = new Label();
            lHead.AutoSize = false;
            lHead.TextAlign = ContentAlignment.MiddleLeft;
            lHead.SetBounds(12, 10, ClientSize.Width - 24, 20);
            lHead.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lHead.Text = "正在读取…";
            Controls.Add(lHead);

            lHint = new Label();
            lHint.AutoSize = false;
            lHint.TextAlign = ContentAlignment.MiddleLeft;
            lHint.ForeColor = Color.FromArgb(122, 128, 138);
            lHint.SetBounds(12, 32, ClientSize.Width - 24, 18);
            lHint.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lHint.Text = "禁用只是「下次开机不再自动启动」，程序本身没删，随时能在这里启用回来。选中一行后点下面的按钮操作。";
            Controls.Add(lHint);

            lv = new ListView();
            lv.View = View.Details;
            lv.FullRowSelect = true;
            lv.MultiSelect = false;
            lv.GridLines = true;
            lv.HideSelection = false;
            lv.ShowItemToolTips = true;
            lv.SetBounds(12, 56, ClientSize.Width - 24, ClientSize.Height - 56 - 56);
            lv.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            lv.Columns.Add("名称", 190);
            lv.Columns.Add("状态", 80);
            lv.Columns.Add("占用内存", 90);
            lv.Columns.Add("位置", 120);
            lv.Columns.Add("启动命令", 380);
            lv.SelectedIndexChanged += delegate { SyncButtons(); };
            lv.DoubleClick += delegate { ToggleSelected(); };
            Controls.Add(lv);

            int by = ClientSize.Height - 42;

            bToggle = new Button();
            bToggle.Text = "禁用自启";
            bToggle.SetBounds(12, by, 110, 30);
            bToggle.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bToggle.Click += delegate { ToggleSelected(); };
            Controls.Add(bToggle);

            bKill = new Button();
            bKill.Text = "结束进程";
            bKill.SetBounds(128, by, 100, 30);
            bKill.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bKill.Click += delegate { KillSelected(); };
            Controls.Add(bKill);

            bOpen = new Button();
            bOpen.Text = "打开位置";
            bOpen.SetBounds(234, by, 100, 30);
            bOpen.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bOpen.Click += delegate
            {
                StartItem it = Selected();
                if (it == null) { NeedSelect(); return; }
                string r = Startup.OpenLocation(it);
                if (r.Length > 0) MessageBox.Show(this, r, "打开位置", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            };
            Controls.Add(bOpen);

            bRefresh = new Button();
            bRefresh.Text = "刷新";
            bRefresh.SetBounds(340, by, 80, 30);
            bRefresh.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bRefresh.Click += delegate { Reload(); };
            Controls.Add(bRefresh);

            // 只有 HKLM 下那几项需要管理员权限。不是管理员就摆一个「重开一次」的入口，
            // 而不是让用户对着「访问被拒绝」发愣。
            if (!Trimmer.IsAdmin)
            {
                Button bElev = new Button();
                bElev.Text = "以管理员身份重新打开";
                bElev.SetBounds(426, by, 170, 30);
                bElev.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
                bElev.Click += delegate
                {
                    if (app != null) app.RelaunchElevated();
                    Close();
                };
                Controls.Add(bElev);
            }

            bClose = new Button();
            bClose.Text = "关闭";
            bClose.SetBounds(ClientSize.Width - 112, by, 100, 30);
            bClose.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
            bClose.Click += delegate { Close(); };
            Controls.Add(bClose);

            Reload();
        }

        // 自检（只给 --startupui 用）：列出表格内容 + 按钮是否都在窗口内。
        internal string DumpForTest()
        {
            StringBuilder b = new StringBuilder();
            try
            {
                b.AppendLine("标题     : " + lHead.Text);
                b.AppendLine("权限     : 管理员=" + Trimmer.IsAdmin + "  进程完整性=" + Startup.CurrentIntegrity());
                b.AppendLine("列       :");
                foreach (ColumnHeader c in lv.Columns) b.Append("           ").Append(c.Text).Append("(").Append(c.Width).Append(")").AppendLine();
                b.AppendLine("行数     : " + lv.Items.Count);
                int i = 0;
                foreach (ListViewItem li in lv.Items)
                {
                    i++;
                    b.Append("  ").Append(i.ToString().PadLeft(2)).Append(". ");
                    for (int c = 0; c < li.SubItems.Count; c++)
                    {
                        if (c > 0) b.Append(" | ");
                        b.Append(li.SubItems[c].Text);
                    }
                    b.AppendLine();
                    if (i >= 40) { b.AppendLine("  …（只列前 40 行）"); break; }
                }
                foreach (Control c in Controls)
                {
                    Button bt = c as Button;
                    if (bt == null) continue;
                    b.AppendLine("按钮     : " + bt.Text.PadRight(22) + " 右边缘 " + bt.Right
                                 + (bt.Right <= ClientSize.Width ? "  ✓" : "  ✗被裁掉"));
                }
            }
            catch (Exception ex) { b.AppendLine("自检失败: " + ex.Message); }
            return b.ToString();
        }

        // 启用/禁用往返自检：切一次再切回来，确认注册表写入与读回一致（不留痕迹）。
        internal string ToggleRoundTripForTest()
        {
            StringBuilder b = new StringBuilder();
            StartItem it = null;
            foreach (ListViewItem li in lv.Items)
            {
                StartItem x = li.Tag as StartItem;
                if (x == null) continue;
                if (x.Source != "HKCU") continue;   // 只测当前用户那组，避免动到 HKLM
                // 优先挑「本来就是禁用」的项：这样往返结束仍是禁用，不会把用户的自启项留成关闭状态。
                if (!Startup.IsEnabled(x)) { it = x; break; }
                if (it == null) it = x;
            }
            if (it == null) { b.AppendLine("往返测试 : 跳过（当前用户组里没有可测的项）"); return b.ToString(); }
            b.AppendLine("往返测试 : 对象 = " + it.Name + "（" + it.Where + "）");
            bool before = Startup.IsEnabled(it);
            b.AppendLine("           初始状态 = " + (before ? "启用" : "禁用"));
            b.Append(Startup.DiagForTest(it));
            string err;
            bool ok1 = Startup.SetEnabled(it, !before, out err);
            b.AppendLine("           切成「" + (!before ? "启用" : "禁用") + "」= " + (ok1 ? "成功" : "失败: " + err)
                         + "，读回 = " + (Startup.IsEnabled(it) ? "启用" : "禁用"));
            bool ok2 = Startup.SetEnabled(it, before, out err);
            b.AppendLine("           切回原状态 = " + (ok2 ? "成功" : "失败: " + err)
                         + "，读回 = " + (Startup.IsEnabled(it) ? "启用" : "禁用")
                         + (Startup.IsEnabled(it) == before ? "  ✓已还原" : "  ✗没还原！"));
            return b.ToString();
        }

        private StartItem Selected()
        {
            if (lv.SelectedItems.Count == 0) return null;
            return lv.SelectedItems[0].Tag as StartItem;
        }

        private void NeedSelect()
        {
            MessageBox.Show(this, "先在上面选中一行。", "开机自启项", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private static string StatusText(StartItem it)
        {
            if (!it.Enabled) return "已禁用";
            return it.RunningMB >= 0 ? "运行中" : "已启用";
        }

        private static Color ColorOf(StartItem it)
        {
            if (!it.Enabled) return Color.FromArgb(152, 156, 164);
            if (it.RunningMB >= 0) return Color.FromArgb(20, 110, 40);
            return Color.FromArgb(30, 34, 42);
        }

        private void SyncButtons()
        {
            StartItem it = Selected();
            if (it == null) { bToggle.Text = "禁用自启"; return; }
            bToggle.Text = it.Enabled ? "禁用自启" : "启用自启";
        }

        private string Summary()
        {
            int n = 0, run = 0, off = 0;
            long total = 0;
            foreach (ListViewItem li in lv.Items)
            {
                StartItem it = li.Tag as StartItem;
                if (it == null) continue;
                n++;
                if (it.RunningMB > 0) { run++; total += it.RunningMB; }
                if (!it.Enabled) off++;
            }
            return "共 " + n + " 项，正在运行 " + run + " 项，合计占用 " + total + " MB 内存"
                 + (off > 0 ? "，已禁用 " + off + " 项" : "") + "。";
        }

        private void Reload()
        {
            try
            {
                lv.BeginUpdate();
                lv.Items.Clear();
                foreach (StartItem it in Startup.Scan())
                {
                    it.Enabled = Startup.IsEnabled(it);
                    ListViewItem li = new ListViewItem(it.Name);
                    li.SubItems.Add(StatusText(it));
                    li.SubItems.Add(it.RunningMB >= 0 ? it.RunningMB + " MB" : "-");
                    li.SubItems.Add(it.Where);
                    li.SubItems.Add(it.Cmd);
                    li.Tag = it;
                    li.ForeColor = ColorOf(it);
                    li.ToolTipText = it.Cmd;
                    lv.Items.Add(li);
                }
                lv.EndUpdate();
                lHead.Text = Summary();
                SyncButtons();
            }
            catch (Exception ex) { lHead.Text = "读取失败: " + ex.Message; }
        }

        private void FillRow(StartItem it)
        {
            foreach (ListViewItem li in lv.Items)
            {
                if (li.Tag != it) continue;
                li.SubItems[1].Text = StatusText(it);
                li.SubItems[2].Text = it.RunningMB >= 0 ? it.RunningMB + " MB" : "-";
                li.ForeColor = ColorOf(it);
                return;
            }
        }

        private void ToggleSelected()
        {
            StartItem it = Selected();
            if (it == null) { NeedSelect(); return; }
            bool was = Startup.IsEnabled(it);
            string err;
            if (!Startup.SetEnabled(it, !was, out err))
            {
                MessageBox.Show(this,
                    "改不了这一项：" + err + "\n\n"
                    + "「所有用户」那一组在 HKLM 下，需要管理员权限。\n"
                    + "可以点下面的「以管理员身份重新打开」，重开这个窗口后再改。",
                    "开机自启项", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            it.Enabled = !was;
            FillRow(it);
            lHead.Text = Summary();
            SyncButtons();
            try { Log.Write("自启项" + (it.Enabled ? "启用" : "禁用") + ": " + it.Name + "（" + it.Where + "）"); }
            catch { }
        }

        private void KillSelected()
        {
            StartItem it = Selected();
            if (it == null) { NeedSelect(); return; }
            if (it.RunningMB < 0)
            {
                MessageBox.Show(this, "「" + it.Name + "」现在没有在运行。", "结束进程",
                                MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (MessageBox.Show(this,
                    "确定要结束正在运行的「" + it.Exe + "」吗？\n"
                    + "合计占用 " + it.RunningMB + " MB。\n\n"
                    + "没有保存的工作会丢失 —— 确认它现在没在干活再点「是」。",
                    "结束进程", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2)
                != DialogResult.Yes) return;

            string r = Startup.Kill(it);
            MessageBox.Show(this, r, "结束进程", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Reload();
        }
    }

    // ==================== 注册表工具 ====================
    internal static class Reg
    {
        public static object Get(string path, string name)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (k == null) return null;
                    return k.GetValue(name);
                }
            }
            catch { return null; }
        }
        public static bool FastStartupDisabled()
        {
            object v = Get(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled");
            return v != null && Convert.ToInt32(v) == 0;
        }
        public static object TdrDelay()
        {
            return Get(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "TdrDelay");
        }

        // ---- 是否有「重启后才生效」的改动挂着 ----
        // 这是「明明没干什么却越来越卡」的一个很隐蔽的来源：Windows Update、驱动安装、
        // 卸载程序都会登记「挂起重启」，之后系统一直用旧状态跑，且不会主动提醒用户。
        public static bool RebootPending()
        {
            try
            {
                if (Get(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "x") != null) return true;
                if (Get(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", "x") != null) return true;
                if (Get(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting", "x") != null) return true;
                // ★ PendingFileRenameOperations 是个大坑：浏览器/更新器把「下次开机时删掉的
                //   临时文件」也登记在这里（例如 Firefox 的 tobedeleted 目录），文件被占用就一直
                //   清不掉，于是「有改动等着重启生效」永远亮着 —— 用户会以为系统真有事。
                //   只有涉及系统目录的改名/删除才真的需要重启才能生效，所以这里只看系统路径。
                object pfr = Get(@"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations");
                string[] arr = pfr as string[];
                if (arr != null)
                {
                    foreach (string one in arr)
                    {
                        if (one == null) continue;
                        string s = one.ToLowerInvariant();
                        if (s.IndexOf("\\windows\\") >= 0 || s.IndexOf("\\system32\\") >= 0
                            || s.IndexOf("\\syswow64\\") >= 0 || s.IndexOf("\\driverstore\\") >= 0) return true;
                    }
                }
                return false;
            }
            catch { return false; }
        }
        public static bool Set(string path, string name, object value)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(path, true))
                {
                    if (k == null) return false;
                    k.SetValue(name, value, RegistryValueKind.DWord);
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool Delete(string path, string name)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(path, true))
                {
                    if (k == null) return false;
                    k.DeleteValue(name, false);
                    return true;
                }
            }
            catch { return false; }
        }

        // ---- 开机自启：用「计划任务 + 最高权限」，这样开机不弹 UAC 也能拿到管理员权限 ----
        public const string TaskName = "SmoothWinTray-AutoStart";

        private static string RunSchTasks(string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit(15000);
                    return (p.HasExited ? p.ExitCode : -1) + " :: " + o.Trim();
                }
            }
            catch (Exception ex) { return "异常: " + ex.Message; }
        }

        public static bool IsAutoStartEnabled()
        {
            string r = RunSchTasks("/query /tn " + TaskName);
            if (r.StartsWith("0")) return true;
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false))
                    return k != null && k.GetValue("SmoothWinTray") != null;
            }
            catch { return false; }
        }

        private static string XmlEsc(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        // schtasks /create 自动生成的计划任务带三个「会自动停掉任务」的默认值：
        //   电池模式不启动 / 切到电池就停止 / 运行 72 小时后停止任务。
        // 前两个在台式机/无电池机器上不触发，但「执行时间上限」和「空闲结束即停止」
        // 会让任务计划程序服务直接把进程杀掉——而且不写应用层日志、不留 WER 记录，
        // 表现就是「托盘悄悄没了，什么都没记」。所以这里自己写 XML 注册：
        // AllowHardTerminate=false + ExecutionTimeLimit=PT0S + StopOnIdleEnd=false。
        public static string TaskXml() { return TaskXml(false); }

        public static string TaskXml(bool auto)
        {
            string who = XmlEsc(System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            string exe = XmlEsc(Application.ExecutablePath);
            StringBuilder b = new StringBuilder();
            b.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-16\"?>");
            b.AppendLine("<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">");
            b.AppendLine("  <RegistrationInfo>");
            b.AppendLine("    <Author>" + who + "</Author>");
            b.AppendLine("    <Description>SmoothWin 常驻监控：开机自动启动，最高权限，不弹 UAC。任务本身不设执行时间上限，也不会被电源/空闲设置停止。</Description>");
            b.AppendLine("    <URI>\\" + TaskName + "</URI>");
            b.AppendLine("  </RegistrationInfo>");
            // 自愈看门狗：每 5 分钟触发一次。托盘活着时新实例会被单实例互斥体挡掉并立刻退出；
            // 托盘若被外部强杀（TerminateProcess 不留任何日志），下一个触发点会自动把它拉回来。
            // MultipleInstancesPolicy=IgnoreNew 保证不会同时跑两个；StartBoundary 取注册时刻前一分钟，
            // 这样注册完就开始按 5 分钟周期计时（实测：TimeTrigger + Repetition + IgnoreNew 可自愈）。
            b.AppendLine("  <Triggers>");
            b.AppendLine("    <LogonTrigger>");
            b.AppendLine("      <Enabled>true</Enabled>");
            b.AppendLine("      <UserId>" + who + "</UserId>");
            b.AppendLine("      <Delay>PT30S</Delay>");
            b.AppendLine("    </LogonTrigger>");
            b.AppendLine("    <TimeTrigger>");
            b.AppendLine("      <Repetition>");
            b.AppendLine("        <Interval>PT5M</Interval>");
            b.AppendLine("        <StopAtDurationEnd>false</StopAtDurationEnd>");
            b.AppendLine("      </Repetition>");
            b.AppendLine("      <StartBoundary>" + DateTime.Now.AddMinutes(-1).ToString("yyyy-MM-dd\\THH:mm:ss") + "</StartBoundary>");
            b.AppendLine("      <Enabled>true</Enabled>");
            b.AppendLine("    </TimeTrigger>");
            b.AppendLine("  </Triggers>");
            b.AppendLine("  <Principals>");
            b.AppendLine("    <Principal id=\"Author\">");
            b.AppendLine("      <UserId>" + who + "</UserId>");
            b.AppendLine("      <LogonType>InteractiveToken</LogonType>");
            b.AppendLine("      <RunLevel>HighestAvailable</RunLevel>");
            b.AppendLine("    </Principal>");
            b.AppendLine("  </Principals>");
            b.AppendLine("  <Settings>");
            b.AppendLine("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
            b.AppendLine("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
            b.AppendLine("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
            b.AppendLine("    <AllowHardTerminate>false</AllowHardTerminate>");
            b.AppendLine("    <StartWhenAvailable>true</StartWhenAvailable>");
            b.AppendLine("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>");
            b.AppendLine("    <IdleSettings>");
            b.AppendLine("      <StopOnIdleEnd>false</StopOnIdleEnd>");
            b.AppendLine("      <RestartOnIdle>false</RestartOnIdle>");
            b.AppendLine("    </IdleSettings>");
            b.AppendLine("    <AllowStartOnDemand>true</AllowStartOnDemand>");
            b.AppendLine("    <Enabled>true</Enabled>");
            b.AppendLine("    <Hidden>false</Hidden>");
            b.AppendLine("    <RunOnlyIfIdle>false</RunOnlyIfIdle>");
            b.AppendLine("    <WakeToRun>false</WakeToRun>");
            b.AppendLine("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
            b.AppendLine("    <Priority>7</Priority>");
            b.AppendLine("    <RestartOnFailure>");
            b.AppendLine("      <Interval>PT1M</Interval>");
            b.AppendLine("      <Count>3</Count>");
            b.AppendLine("    </RestartOnFailure>");
            b.AppendLine("  </Settings>");
            b.AppendLine("  <Actions Context=\"Author\">");
            b.AppendLine("    <Exec>");
            b.AppendLine("      <Command>" + exe + "</Command>");
            // --auto：让被任务拉起的实例能区分「自启」和「用户自己点的」
            if (auto) b.AppendLine("      <Arguments>--auto</Arguments>");
            b.AppendLine("    </Exec>");
            b.AppendLine("  </Actions>");
            b.AppendLine("</Task>");
            return b.ToString();
        }

        // 用自定义 XML 注册计划任务；失败时返回原因，由调用方回退到 schtasks 的默认模板。
        public static string RegisterAutoStartTask() { return RegisterAutoStartTask(false); }

        // auto = true 时给计划任务带上 --auto 参数：任务拉起的实例知道
        // 「我是被自启机制叫起来的」，于是会尊重用户的「手动退出」记录（见 QuitMark）。
        public static string RegisterAutoStartTask(bool auto)
        {
            if (!Trimmer.IsAdmin) return "需要管理员权限";
            string xml = Path.Combine(Path.GetTempPath(), "SmoothWinTray-task.xml");
            try
            {
                File.WriteAllText(xml, TaskXml(auto), new UnicodeEncoding(false, true));
                string r = RunSchTasks("/create /tn \"" + TaskName + "\" /xml \"" + xml + "\" /f");
                if (!r.StartsWith("0")) return r;
                return "0 :: 已用自定义模板注册";
            }
            catch (Exception ex) { return "异常: " + ex.Message; }
            finally { try { if (File.Exists(xml)) File.Delete(xml); } catch { } }
        }

        // 用户主动启动时把可能被停用的任务恢复回来
        //（用户之前让程序「关上」时就是整体停用的，重新启动时顺手修好）。

        // 给自检/命令行用：自启任务的模板里有没有 --auto 参数
        public static string QueryAutoArg()
        {
            string q = RunSchTasks("/query /tn \"" + TaskName + "\" /xml");
            if (!q.StartsWith("0")) return "未注册（没有开机自启）";
            return q.IndexOf("--auto", StringComparison.OrdinalIgnoreCase) >= 0
                   ? "已注册，模板含 --auto（会尊重「手动退出」）"
                   : "已注册，但模板是旧版（缺 --auto，会把退出的托盘又拉回来）";
        }

        public static string EnableTimerTrigger()
        {
            string r = RunSchTasks("/change /tn \"" + TaskName + "\" /enable");
            if (r.StartsWith("0")) return "已恢复";
            return "未恢复: " + r;
        }

        // 用户主动启动时把自启任务恢复到「正常状态」：
        //   · 之前点「退出」时被停用的 → 重新启用；
        //   · 老版本注册的（动作里没有 --auto）→ 重新注册一次，
        //     否则它会一直无视「手动退出」记录，把用户退掉的托盘又拉回来。
        // 返回空串 = 不需要动。
        public static string EnsureTimerTrigger()
        {
            string q = RunSchTasks("/query /tn \"" + TaskName + "\" /xml");
            if (!q.StartsWith("0")) return "";     // 没注册开机自启，不关这里的事

            bool needRegister = q.IndexOf("--auto", StringComparison.OrdinalIgnoreCase) < 0;
            if (needRegister)
            {
                if (!Trimmer.IsAdmin) return "自启任务的启动参数是旧版（缺少 --auto），需要管理员才能修";
                string rx = RegisterAutoStartTask(true);
                return rx.StartsWith("0") ? "自启任务已升级（补上 --auto 参数）" : ("自启任务升级失败: " + rx);
            }

            // 任务存在且模板正确：把可能被停用的状态恢复回来
            string e = RunSchTasks("/change /tn \"" + TaskName + "\" /enable");
            return e.StartsWith("0") ? "自启任务已重新启用" : "";
        }

        public static string SetAutoStart(bool on)
        {
            if (on)
            {
                if (!Trimmer.IsAdmin) return "启用开机自启需要管理员权限，请先「以管理员身份重新启动」。";
                string rx = RegisterAutoStartTask(true);
                if (rx.StartsWith("0")) return "已启用（计划任务，最高权限，开机不弹 UAC；已关闭执行时间上限与电源/空闲停止）";
                Log.Write("自定义任务模板注册失败，回退默认模板: " + rx);
                string args = "/create /tn " + TaskName + " /tr \"" + Application.ExecutablePath +
                              "\" /sc onlogon /rl highest /delay 0000:30 /f";
                string r = RunSchTasks(args);
                return r.StartsWith("0") ? "已启用（计划任务，最高权限，开机不弹 UAC）" : "启用失败: " + r;
            }
            else
            {
                string r = RunSchTasks("/delete /tn " + TaskName + " /f");
                try
                {
                    using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                        if (k != null) k.DeleteValue("SmoothWinTray", false);
                }
                catch { }
                return "已关闭";
            }
        }
    }

    // ==================== 「手动退出」记录 ====================
    // 需求：用户点「退出」就必须真的退出，而不是 5 分钟后被自愈看门狗又拉起来。
    // 难点在于要同时满足三件事：
    //   ① 手动退出后不再复活；
    //   ② 用户下次主动启动（双击图标 / 开始菜单）时能正常起来，并且自启能力恢复；
    //   ③ 该被自愈的情况（被外部强杀、界面假死）仍然要自愈，不能因为怕复活就砍掉看门狗。
    // 做法：手动退出时在数据目录里写一个「退出记录」文件。
    //   计划任务的 5 分钟触发把新实例拉起来后，新实例启动第一件事就是看这个记录：
    //   记录还在 → 静默退出，不复活。
    //   用户主动双击图标时，新实例启动时会先把记录清掉，于是恢复正常；
    //   计划任务拉起的那些实例因为已经提前 return，不会误把记录清掉。
    //   记录里记着「这次开机的时刻」，重启后自动作废 → 重启后自启照常工作。
    // 记录文件放在各自的数据目录里，所以同一个账户下用不同数据目录跑自动化测试时
    // 互不干扰，不会误伤正在运行的真实实例。
    internal static class QuitMark
    {
        // ★ 退出记录用「文件」保存，不用内核事件。
        //   原因：具名内核对象在「最后一个句柄关闭」时就被销毁。手动退出的进程
        //   CreateEvent → SetEvent → 进程退出 → 记录跟着一起消失，下一个 --auto 实例
        //   看到的永远是「没有记录」，于是托盘又被拉回来（实测：13:07:51 手动退出，
        //   13:08:02 自启就把实例拉起来了）。文件没有这个问题：进程退出它还在。
        //   重启后按「开机时间」判过期 —— 重启本来就该恢复自启。
        private static string MarkPath { get { return Path.Combine(Config.Dir, "manual-exit.mark"); } }

        // 当前这次开机的标识（用开机时刻表示）：记录里存的跟它不一样 = 中间重启过。
        private static string BootId()
        {
            try
            {
                // .NET Framework 4.x 没有 Environment.TickCount64（那是 .NET Core 的），
                // 用 GetTickCount 拼一个 64 位版本；拿不到就退化成「不判过期」。
                long ms = (long)Native.UptimeMs();
                return DateTime.Now.Subtract(TimeSpan.FromMilliseconds(ms)).ToString("yyyyMMddHHmm");
            }
            catch { return ""; }
        }

        private static string SidPart()
        {
            string who = "default";
            try { who = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value; }
            catch { }
            // 反斜杠是事件名里唯一不能出现的字符，统一换成下划线
            return who.Replace('\\', '_');
        }

        // 数据目录标签：同一个账户下用不同数据目录跑实例（自动化实测）时，
        // 「退出请求」事件互不干扰，测试不会误伤正在运行的真实实例。
        private static string DirTag()
        {
            try
            {
                string d = Config.Dir ?? "";
                int h = 17;
                for (int i = 0; i < d.Length; i++) h = h * 31 + d[i];
                return (h & 0x7fffffff).ToString();
            }
            catch { return "0"; }
        }

        // 「请正在运行的那个实例退出」用的事件名（给命令行 --quit 用，
        // 这样自动化测试和脚本走的也是程序里真正的退出路径，而不是直接杀进程）。
        // 这个「退出请求」仍然用内核事件：它只需要「当下传到」正在运行的那个实例，
        // 不需要在进程退出后继续存在（退出记录才需要，所以那份改成了文件）。
        public static string ExitEventName() { return "Local\\SmoothWinTray_Exit_" + SidPart() + "_" + DirTag(); }

        // 退出记录是否还在（重启后自动作废）
        public static bool Pending()
        {
            try
            {
                if (!File.Exists(MarkPath)) return false;
                string txt = (File.ReadAllText(MarkPath) ?? "").Trim();
                string boot = BootId();
                // 记录里的开机时刻跟当前对不上 = 中间重启过 → 记录作废，自启照常工作
                if (boot.Length > 0 && txt.Length > 0 && txt != boot)
                {
                    try { File.Delete(MarkPath); } catch { }
                    return false;
                }
                return true;
            }
            catch { return false; }
        }

        // 写下退出记录（手动退出时调用）
        public static bool Set()
        {
            try
            {
                Directory.CreateDirectory(Config.Dir);
                File.WriteAllText(MarkPath, BootId(), new UTF8Encoding(false));
                return true;
            }
            catch { return false; }
        }

        // 清掉退出记录（用户主动启动时调用），返回清掉前它是否存在
        public static bool Consume()
        {
            try
            {
                bool was = Pending();
                if (was) File.Delete(MarkPath);
                return was;
            }
            catch { return false; }
        }

    }

    // ==================== 系统优化项（可还原） ====================
    internal class FixItem
    {
        public string Key, Name, Desc;
        public object Value;
        public bool OnlyIfS0;
        // 只在「本机近期确实出现过显卡驱动崩溃(事件 4101)」时才应用。
        // 用于那些「有收益但也有代价」的优化项：没病就别吃药。
        public bool OnlyIfTdr;
    }

    internal static class SystemFix
    {
        public static bool HasS0
        {
            get
            {
                try { return Events.Count("Microsoft-Windows-Kernel-Power", 506, 168) > 0; }
                catch { return false; }
            }
        }

        // 近 30 天内是否出现过「显示器驱动程序已停止响应，并且已成功恢复」(Display 事件 4101)。
        public static bool HasRecentTdr
        {
            get
            {
                try { return Events.Count("Display", 4101, 24 * 30) > 0; }
                catch { return false; }
            }
        }

        public static List<FixItem> Build()
        {
            List<FixItem> l = new List<FixItem>();
            l.Add(new FixItem { Key = @"SYSTEM\CurrentControlSet\Control\Session Manager\Power", Name = "HiberbootEnabled", Value = 0,
                Desc = "关闭快速启动：关机时真正重置内核状态（这是「只有物理重启才恢复」的根因）" });
            l.Add(new FixItem { Key = @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", Name = "TdrDelay", Value = 10,
                Desc = "显卡驱动超时 2 → 10 秒：减少 TDR 崩溃（事件 4101）" });
            l.Add(new FixItem { Key = @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", Name = "TdrDdiDelay", Value = 10,
                Desc = "显卡驱动 DDI 超时 2 → 10 秒" });
            l.Add(new FixItem { Key = @"SYSTEM\CurrentControlSet\Control\CrashControl", Name = "AutoReboot", Value = 1,
                Desc = "蓝屏后自动重启，避免卡死在蓝屏界面" });
            l.Add(new FixItem { Key = @"SYSTEM\CurrentControlSet\Control\Power", Name = "PlatformAoAcOverride", Value = 0, OnlyIfS0 = true,
                Desc = "关闭「连接待机 / Modern Standby」：待机恢复是显卡驱动崩溃的高发点" });
            l.AddRange(BuildGpuUlps());
            // MPO（多平面覆盖）是显卡驱动崩溃的常见放大器，虚拟显示器/远控软件与它尤其容易冲突。
            // 关闭它能显著减少 4101，代价是视频播放/窗口化游戏的合成效率略降，
            // 所以只在近 30 天确实崩过时才应用（OnlyIfTdr）。
            l.Add(new FixItem { Key = @"SOFTWARE\Microsoft\Windows\Dwm", Name = "OverlayTestMode", Value = 5, OnlyIfTdr = true,
                Desc = "关闭 MPO 多平面覆盖：减少显卡驱动「已停止响应并恢复」（事件 4101）" });
            return l;
        }

        // ---- 显卡深度省电（ULPS）----
        // AMD 显卡驱动空闲时会把 GPU 降到 Ultra Low Power State，唤醒失败就是
        // 「显示器驱动程序 xxx 已停止响应，并且已成功恢复」(事件 4101 / TDR) 的经典成因。
        // 只处理驱动确实写了 EnableUlps 的显卡（NVIDIA / Intel 没有这个值，自动跳过），
        // 所以这段是通用的：装了什么显卡就处理什么显卡。
        public const string GpuClass = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

        public static List<FixItem> BuildGpuUlps()
        {
            List<FixItem> l = new List<FixItem>();
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(GpuClass))
                {
                    if (k == null) return l;
                    foreach (string sub in k.GetSubKeyNames())
                    {
                        using (RegistryKey s = k.OpenSubKey(sub))
                        {
                            if (s == null) continue;
                            if (s.GetValue("EnableUlps") == null) continue;
                            object desc = s.GetValue("DriverDesc");
                            l.Add(new FixItem
                            {
                                Key = GpuClass + "\\" + sub,
                                Name = "EnableUlps",
                                Value = 0,
                                Desc = "关闭显卡深度省电 ULPS（" + (desc == null ? sub : desc.ToString())
                                     + "）：减少「显示器驱动程序已停止响应」事件 4101"
                            });
                        }
                    }
                }
            }
            catch { }
            return l;
        }

        public static string BackupPath { get { return Path.Combine(Config.Dir, "sysfix-backup.ini"); } }

        public static string StatusText()
        {
            StringBuilder b = new StringBuilder();
            foreach (FixItem it in Build())
            {
                object cur = Reg.Get(it.Key, it.Name);
                bool ok = cur != null && cur.ToString() == it.Value.ToString();
                b.AppendLine((ok ? "[已优化] " : "[未设置] ") + it.Name + " = " + (cur == null ? "默认" : cur.ToString()) + "   （目标 " + it.Value + "）");
            }
            b.AppendLine();
            b.AppendLine("连接待机(Modern Standby) : " + (HasS0 ? "正在使用（建议关闭）" : "未检测到"));
            return b.ToString();
        }

        public static string Apply()
        {
            if (!Trimmer.IsAdmin) return "需要管理员权限。请右键托盘图标 → 以管理员身份重新启动，再试一次。";
            StringBuilder log = new StringBuilder();
            List<FixItem> items = Build();

            // 备份原始值：已存在的条目绝不覆盖（保留最初状态，保证可完整还原）；
            // 后续版本新增的优化项以「追加」方式补进备份，否则新项将无法还原。
            {
                StringBuilder bk = new StringBuilder();
                string have = "";
                try { if (File.Exists(BackupPath)) have = File.ReadAllText(BackupPath); } catch { }
                if (have.Length > 0) bk.Append(have.TrimEnd('\r', '\n')).AppendLine();
                int added = 0;
                foreach (FixItem it in items)
                {
                    string tag = it.Key + "|" + it.Name + "|";
                    if (have.IndexOf(tag, StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    object old = Reg.Get(it.Key, it.Name);
                    bk.AppendLine(tag + (old == null ? "<NULL>" : old.ToString()));
                    added++;
                }
                if (!File.Exists(BackupPath) || added > 0)
                {
                    try { File.WriteAllText(BackupPath, bk.ToString(), new UTF8Encoding(true)); }
                    catch (Exception ex) { return "写入备份失败，已中止: " + ex.Message; }
                }
            }

            int n = 0;
            foreach (FixItem it in items)
            {
                if (it.OnlyIfS0 && !HasS0) { log.AppendLine("[跳过] " + it.Desc + "（本机未使用连接待机）"); continue; }
                if (it.OnlyIfTdr && !HasRecentTdr) { log.AppendLine("[跳过] " + it.Desc + "（近 30 天没有显卡驱动崩溃记录）"); continue; }
                object cur = Reg.Get(it.Key, it.Name);
                if (cur != null && cur.ToString() == it.Value.ToString()) { log.AppendLine("[已是] " + it.Desc); continue; }
                if (Reg.Set(it.Key, it.Name, it.Value)) { log.AppendLine("[设置] " + it.Desc); n++; }
                else log.AppendLine("[失败] " + it.Desc);
            }
            log.AppendLine();
            log.AppendLine("本次修改 " + n + " 项。备份: " + BackupPath);
            log.AppendLine("注意: 关闭快速启动后，下次「关机」将是真正的完全关机（开机会慢几秒，这是正常的）。");
            return log.ToString();
        }

        public static string Restore()
        {
            if (!Trimmer.IsAdmin) return "需要管理员权限。";
            if (!File.Exists(BackupPath)) return "没有找到备份文件 " + BackupPath + "，无法还原。";
            StringBuilder log = new StringBuilder();
            foreach (string raw in File.ReadAllLines(BackupPath))
            {
                string[] p = raw.Split('|');
                if (p.Length < 3) continue;
                string key = p[0], name = p[1], old = p[2];
                if (old == "<NULL>")
                {
                    if (Reg.Delete(key, name)) log.AppendLine("[移除] " + name + "（原本不存在，已删除）");
                    else log.AppendLine("[跳过] " + name + "（原本不存在，且删除失败）");
                }
                else
                {
                    int iv;
                    object v = int.TryParse(old, out iv) ? (object)iv : (object)old;
                    if (Reg.Set(key, name, v)) log.AppendLine("[还原] " + name + " = " + old);
                    else log.AppendLine("[失败] " + name);
                }
            }
            return log.ToString();
        }
    }

    // ==================== 状态窗口 ====================
    // 用户要求：① 别再是一大坨纯文本，要好看；② 从通知点进来不能「未响应」。
    // 对策：卡片式布局（关键数字大字号 + 进度条 + 状态色），
    //       采样和字符串拼接全部丢到后台线程，UI 线程只负责把数字贴到控件上。
    //
    // 说明：这里刻意不复用 BuildReport() 那套纯文本。文字报告仍然保留，
    // 但退居到「详细报告」按钮后面，需要时再打开。
    internal class UiData
    {
        public bool Ok;
        public string Time = "", Uptime = "", Perm = "", RunState = "";
        public long AvailMB, TotalMB, CommitMB, CommitLimitMB, CommitPct;
        public long CompressionMB, StandbyMB, ModifiedMB, PoolNonPagedMB, PoolPagedMB;
        public int Procs, Threads, Handles;
        public double HardFaultsPerSec = -1, DpcPct = -1, InterruptPct = -1;
        public double CpuPct = -1, DiskBusyPct = -1, DiskQueue = -1, DiskMBps = -1;
        public int CommitThreshold, HardFaultThreshold;
        public bool FastStartupOff, TdrOk, AutoStart, RebootPending;
        public string TdrText = "", DevText = "", StartupText = "";
        public int BadDevices, Tdr4101 = -1, Whea = -1;
        public string StressText = "", LoadText = "", LeakText = "", LastTrim = "", PerfError = "";
        public string Advice = "", DeviceAdvice = "";
        public bool NeedHelp;
        public string StressKind = "";
        public int StressStreak, StressFixTries;
        public string FullText = "";
    }

    // 一个小圆点，用来表示「当前状态」（绿/黄/红）
    internal class DotPanel : Panel
    {
        private Color _dot = Color.Gray;
        public Color Dot { get { return _dot; } set { _dot = value; } }
        public DotPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            try
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                using (SolidBrush b = new SolidBrush(Dot))
                    e.Graphics.FillEllipse(b, 1, 1, Width - 3, Height - 3);
            }
            catch { }
        }
    }

    // 细进度条：把百分比变成一根看得见的条，比读数字快得多
    internal class BarPanel : Panel
    {
        private double _ratio;
        private Color _fill = Color.FromArgb(46, 160, 67);
        public double Ratio { get { return _ratio; } set { _ratio = value; } }
        public Color Fill { get { return _fill; } set { _fill = value; } }
        private static readonly Color Track = Color.FromArgb(233, 236, 241);
        public BarPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            try
            {
                using (SolidBrush t = new SolidBrush(Track))
                    e.Graphics.FillRectangle(t, 0, 0, Width, Height);
                double r = Ratio;
                if (r < 0) r = 0;
                if (r > 1) r = 1;
                int w = (int)Math.Round(Width * r);
                if (w > 0)
                    using (SolidBrush fb = new SolidBrush(Fill))
                        e.Graphics.FillRectangle(fb, 0, 0, w, Height);
            }
            catch { }
        }
    }

    // 白底卡片 + 左侧色条。所有内容都摆在卡片里，不再是「一大段文字」。
    internal class CardPanel : Panel
    {
        private Color _accent = Color.FromArgb(206, 212, 220);
        public Color Accent { get { return _accent; } set { _accent = value; } }
        public CardPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Color.White;
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            try
            {
                using (Pen p = new Pen(Color.FromArgb(226, 230, 237)))
                    e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
                using (SolidBrush b = new SolidBrush(Accent))
                    e.Graphics.FillRectangle(b, 0, 0, 4, Height - 1);
            }
            catch { }
        }
    }

    internal class StatusForm : Form
    {
        private TrayApp app;
        private System.Windows.Forms.Timer tick;
        private CheckBox cAutoRefresh;
        private Label foot;

        private DotPanel dot;
        private Label lHead, lSub;

        private CardPanel[] card = new CardPanel[4];
        private Label[] cardTitle = new Label[4];
        private Label[] cardValue = new Label[4];
        private Label[] cardSub = new Label[4];
        private BarPanel[] cardBar = new BarPanel[4];

        private CardPanel cardSys, cardEvt, cardAdv;
        private Label lSysHead, lEvtHead, lAdvHead, lAdvBody;
        private Label[] sysK = new Label[5];
        private Label[] sysV = new Label[5];
        private Label[] evtK = new Label[5];
        private Label[] evtV = new Label[5];

        // 后台采样闸门：上一轮还没回来就不再发新的，避免堆积
        private volatile bool busy;
        private UiData latest;

        private static readonly Color Ink = Color.FromArgb(30, 34, 42);
        private static readonly Color Gray = Color.FromArgb(122, 128, 138);
        private static readonly Color Green = Color.FromArgb(46, 160, 67);
        private static readonly Color Amber = Color.FromArgb(198, 138, 22);
        private static readonly Color Red = Color.FromArgb(200, 60, 60);

        public StatusForm(TrayApp owner)
        {
            app = owner;
            Text = "SmoothWin 常驻监控";
            // ★ 宽度从 920 加到 1010：原来那 10 个按钮加起来 980 像素宽，
            //   920 的客户区装不下，最后一个「退出」直接被裁到看不见（用户实测反馈）。
            //   本机主屏 2560×1440，1010 宽完全放得下；标题栏的「自动刷新」也仍然贴右侧。
            ClientSize = new Size(1010, 724);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            MinimizeBox = true;
            ShowInTaskbar = true;
            BackColor = Color.FromArgb(244, 246, 249);
            Font = new Font("Microsoft YaHei UI", 9f);
            try { Icon = owner.AppIcon; } catch { }

            // ---------- 顶部标题栏 ----------
            Panel head = new Panel();
            head.SetBounds(0, 0, ClientSize.Width, 70);
            head.BackColor = Color.White;
            Controls.Add(head);

            dot = new DotPanel();
            dot.Dot = Color.FromArgb(150, 150, 150);
            dot.BackColor = Color.White;
            dot.SetBounds(20, 22, 14, 14);
            head.Controls.Add(dot);

            lHead = Mk("SmoothWin 常驻监控", 13f, true, Ink);
            lHead.SetBounds(44, 12, 460, 26);
            head.Controls.Add(lHead);

            lSub = Mk("正在读取状态…", 9f, false, Gray);
            lSub.SetBounds(46, 40, 700, 18);
            head.Controls.Add(lSub);

            cAutoRefresh = new CheckBox();
            cAutoRefresh.Text = "自动刷新";
            cAutoRefresh.Checked = true;
            cAutoRefresh.ForeColor = Gray;
            cAutoRefresh.BackColor = Color.Transparent;
            cAutoRefresh.SetBounds(ClientSize.Width - 116, 24, 96, 22);
            cAutoRefresh.CheckedChanged += delegate { if (cAutoRefresh.Checked) Refresh1(); };
            head.Controls.Add(cAutoRefresh);

            // ---------- 四张关键指标卡 ----------
            string[] titles = { "可用内存", "提交内存", "换页压力", "系统负载" };
            // 按窗口宽度平分，别写死 210：窗口一加宽就留出一条空当，看着像没画完。
            int gap = 16, cy = 86, ch = 108;
            int cw = (ClientSize.Width - 32 - gap * 3) / 4;
            for (int i = 0; i < 4; i++)
            {
                CardPanel c = new CardPanel();
                c.SetBounds(16 + i * (cw + gap), cy, cw, ch);
                Controls.Add(c);
                card[i] = c;

                cardTitle[i] = Mk(titles[i], 9f, false, Gray);
                cardTitle[i].SetBounds(16, 12, cw - 28, 18);
                c.Controls.Add(cardTitle[i]);

                cardValue[i] = Mk("—", 17f, true, Ink);
                cardValue[i].SetBounds(16, 32, cw - 28, 34);
                c.Controls.Add(cardValue[i]);

                cardSub[i] = Mk("", 8.5f, false, Color.FromArgb(142, 148, 158));
                cardSub[i].SetBounds(16, 68, cw - 28, 18);
                cardSub[i].AutoEllipsis = true;   // 太长就截断加省略号，不能换行把卡片撑破
                c.Controls.Add(cardSub[i]);

                BarPanel bp = new BarPanel();
                bp.SetBounds(16, 92, cw - 32, 6);
                c.Controls.Add(bp);
                cardBar[i] = bp;
            }

            // ---------- 左：系统设置 ----------
            int halfW = (ClientSize.Width - 32 - 16) / 2;
            cardSys = new CardPanel();
            cardSys.SetBounds(16, 210, halfW, 190);
            Controls.Add(cardSys);
            lSysHead = Mk("系统设置", 10.5f, true, Ink);
            lSysHead.SetBounds(18, 12, 400, 20);
            cardSys.Controls.Add(lSysHead);
            string[] sk = { "快速启动", "显卡超时 TdrDelay", "开机自启", "设备驱动", "挂起重启" };
            for (int i = 0; i < 5; i++)
            {
                sysK[i] = Mk(sk[i], 9f, false, Gray);
                sysK[i].SetBounds(18, 44 + i * 26, 148, 20);
                cardSys.Controls.Add(sysK[i]);
                sysV[i] = Mk("—", 9f, false, Ink);
                sysV[i].SetBounds(170, 44 + i * 26, cardSys.Width - 188, 20);
                sysV[i].AutoEllipsis = true;
                cardSys.Controls.Add(sysV[i]);
            }

            // ---------- 右：最近事件 ----------
            cardEvt = new CardPanel();
            cardEvt.SetBounds(16 + halfW + 16, 210, halfW, 190);
            Controls.Add(cardEvt);
            lEvtHead = Mk("最近情况", 10.5f, true, Ink);
            lEvtHead.SetBounds(18, 12, 380, 20);
            cardEvt.Controls.Add(lEvtHead);
            string[] ek = { "显卡驱动崩溃（24 小时）", "WHEA 硬件错误（24 小时）", "待机缓存 / 已修改", "内存压缩", "进程 / 线程 / 句柄" };
            for (int i = 0; i < 5; i++)
            {
                evtK[i] = Mk(ek[i], 9f, false, Gray);
                evtK[i].SetBounds(18, 44 + i * 26, 190, 20);
                cardEvt.Controls.Add(evtK[i]);
                evtV[i] = Mk("—", 9f, false, Ink);
                evtV[i].SetBounds(212, 44 + i * 26, cardEvt.Width - 230, 20);
                evtV[i].AutoEllipsis = true;
                cardEvt.Controls.Add(evtV[i]);
            }

            // ---------- 底部结论卡 ----------
            // ★ 结论卡从 232 加到 280 高：绿分支那段「程序只整理没在用的后台进程…」
            //   是 3~5 行，184 像素的正文框装不下，多出来的部分被下面的页脚盖住。
            cardAdv = new CardPanel();
            cardAdv.SetBounds(16, 412, ClientSize.Width - 32, 280);
            Controls.Add(cardAdv);
            lAdvHead = Mk("状态", 10.5f, true, Ink);
            lAdvHead.SetBounds(18, 12, 500, 20);
            cardAdv.Controls.Add(lAdvHead);
            lAdvBody = Mk("正在读取状态…", 9.5f, false, Color.FromArgb(58, 64, 74));
            lAdvBody.SetBounds(18, 38, cardAdv.Width - 36, cardAdv.Height - 50);
            // 兜底：万一日志行特别长（例如带路径的注意项），宁可截断加省略号，
            // 也不能让它溢出到卡片外面去压住页脚。
            lAdvBody.AutoEllipsis = true;
            cardAdv.Controls.Add(lAdvBody);
            advCardBaseH = cardAdv.Height;
            advBodyBaseH = lAdvBody.Height;

            foot = Mk("", 8.5f, false, Color.FromArgb(150, 156, 166));
            foot.SetBounds(18, 700, ClientSize.Width - 36, 18);
            Controls.Add(foot);

            // ---------- 按钮 ----------
            // 按钮自动换行：窗口宽度或字体一变，原来写死的 x 坐标就会把末尾的按钮挤出去
            // （「退出」看不见就是这么来的）。改成按可用宽度折行，永远都在框里。
            // 起始 y 也跟着结论卡算：原来写死 674，结论卡加高到 692 之后就会压在卡片上。
            btnY = cardAdv.Bottom + 10;
            int bx = 16;
            bx = AddBtn("立即整理", bx, 100, delegate { app.TrimNow("手动"); });
            bx = AddBtn("暂停 / 恢复", bx, 100, delegate { app.TogglePause(); });
            bx = AddBtn("设置…", bx, 80, delegate { app.ShowSettings(); });
            bx = AddBtn("详细报告", bx, 100, delegate { ShowDetail(); });
            bx = AddBtn("打开日志", bx, 90, delegate { app.OpenLog(); });
            bx = AddBtn("设备检查", bx, 90, delegate { app.ShowDevices(); });
            bx = AddBtn("自启项", bx, 90, delegate { app.ShowStartup(); });
            bx = AddBtn("后台应用", bx, 100, delegate { app.ShowApps(); });
            bx = AddBtn("复制报告", bx, 90, delegate { app.CopyReport(); });
            bx = AddBtn("隐藏窗口", bx, 90, delegate { Hide(); });
            // 用户第一反应是关掉窗口上的按钮，而不是去翻右键菜单 —— 出口要放在看得见的地方。
            AddBtn("退出", bx, 90, delegate { app.ExitApp("状态窗口", true); });

            LayoutBottom();

            tick = new System.Windows.Forms.Timer();
            tick.Interval = 1000;
            tick.Tick += delegate { Refresh1(); };
            tick.Start();
        }

        private static Label Mk(string text, float size, bool bold, Color fore)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = false;
            l.Font = new Font("Microsoft YaHei UI", size, bold ? FontStyle.Bold : FontStyle.Regular);
            l.ForeColor = fore;
            l.BackColor = Color.Transparent;
            l.TextAlign = ContentAlignment.MiddleLeft;
            return l;
        }

        // 按钮先收集起来，最后统一排版（LayoutBottom）。
        private readonly List<Button> btnList = new List<Button>();
        private int btnY = 674;

        private int AddBtn(string text, int x, int w, EventHandler h)
        {
            Button b = new Button();
            b.Text = text;
            b.FlatStyle = FlatStyle.System;
            b.Click += h;
            b.Tag = w;                       // 记下宽度，重新排版时还要用
            Controls.Add(b);
            btnList.Add(b);
            return x + w + 6;
        }

        // 按钮 / 页脚 / 结论卡一起重新排版。
        // 关键：按钮按可用宽度自动折行，起始 y 跟着结论卡的实际高度走 ——
        // 写死坐标正是「退出」被裁掉、页脚被正文压住这两个 bug 的根源。
        private void LayoutBottom()
        {
            try
            {
                if (btnList.Count == 0) return;
                int y = cardAdv.Bottom + 10;
                int x = 16;
                for (int i = 0; i < btnList.Count; i++)
                {
                    Button b = btnList[i];
                    int w = (b.Tag == null) ? 90 : (int)b.Tag;
                    if (x + w > ClientSize.Width - 16) { x = 16; y += 34; }
                    b.SetBounds(x, y, w, 30);
                    x += w + 6;
                }
                btnY = y;
                foot.SetBounds(18, y + 40, ClientSize.Width - 36, 18);
                int need = y + 40 + 18 + 12;
                // 窗口也跟着内容收放：结论卡短了就收回来，免得底下留一大片空。
                if (need < 420) need = 420;
                if (need != ClientSize.Height) ClientSize = new Size(ClientSize.Width, need);
            }
            catch { }
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Refresh1();
        }

        // ★ 关键修复：这里绝不做任何采样或拼字符串的活儿。
        //   以前每秒在 UI 线程上跑一次 BuildReport()（内含 4 次事件日志查询，
        //   每次约 300 毫秒），窗口必然「未响应」。现在只负责派活。
        public void Refresh1()
        {
            if (IsDisposed || !IsHandleCreated || !Visible) return;
            if (busy) return;
            if (!cAutoRefresh.Checked) { foot.Text = "配置目录: " + Config.Dir + "    （自动刷新已关闭）"; return; }
            busy = true;
            ThreadPool.QueueUserWorkItem(delegate
            {
                UiData d = null;
                try { d = app.BuildUiData(); }
                catch (Exception ex) { try { Log.Write("界面刷新失败: " + ex.Message); } catch { } }
                try
                {
                    if (!IsDisposed && IsHandleCreated)
                        BeginInvoke((MethodInvoker)delegate
                        {
                            busy = false;
                            if (d != null) Apply(d);
                        });
                    else busy = false;
                }
                catch { busy = false; }
            });
        }

        // 自检专用：Refresh1 把数据构建丢给线程池，紧接着截图会拍到「正在读取状态…」。
        // 这里泵消息等它填好，最多等 waitMs 毫秒，拿到数据或超时就返回。
        internal bool Refresh1AndWait(int waitMs)
        {
            Refresh1();
            long t0 = Environment.TickCount;
            while (Environment.TickCount - t0 < waitMs)
            {
                Application.DoEvents();
                System.Threading.Thread.Sleep(50);
                if (latest != null) return true;
            }
            return latest != null;
        }

        // 结论卡只有 100 像素高，放不下整段；只留前几行，其余引导用户点「详细报告」
        // 结论卡正文按真实渲染高度自适应。绿分支那段是 3~5 行，写死高度就一定会裁。
        private int advCardBaseH = 0, advBodyBaseH = 0;
        private void FitAdvBody()
        {
            try
            {
                if (advCardBaseH <= 0) return;
                Size sz = TextRenderer.MeasureText(lAdvBody.Text, lAdvBody.Font,
                            new Size(lAdvBody.Width, int.MaxValue),
                            TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);
                int need = sz.Height + 8;
                if (need < 60) need = 60;
                if (need > 460) need = 460;            // 再长就交给 AutoEllipsis，别把窗口撑爆
                // ★ 卡片高度跟着正文走：够高就变高，只有两行就缩回去。
                //   以前固定 280 像素，绿分支那三行只占 65 像素，下面一大片空白很难看。
                //   注意：cardH 必须用「新的」need 算，不能用 lAdvBody.Bottom ——
                //   那还是上一轮的旧高度，第一次刷新会算出 280，要等第二次才缩回来。
                int cardH = Math.Max(112, need + lAdvBody.Top + 12);
                if (need == lAdvBody.Height && cardAdv.Height == cardH) return;
                lAdvBody.Height = need;
                cardAdv.Height = cardH;
                LayoutBottom();                        // 按钮和页脚跟着往下让位
            }
            catch { }
        }

        // 排版自检（只给 --uicheck 用）：把「按钮有没有被裁、页脚有没有被压住」
        // 变成可断言的数字，而不是靠肉眼看截图。
        internal string LayoutForTest()
        {
            StringBuilder b = new StringBuilder();
            try
            {
                b.AppendLine("窗口客户区   : " + ClientSize.Width + " x " + ClientSize.Height);
                b.AppendLine("结论卡       : " + cardAdv.Left + "," + cardAdv.Top + " " + cardAdv.Width + " x " + cardAdv.Height);
                b.AppendLine("结论正文     : " + lAdvBody.Left + "," + lAdvBody.Top + " " + lAdvBody.Width + " x " + lAdvBody.Height);
                int worst = 0;
                foreach (Button bt in btnList)
                {
                    bool inside = bt.Right <= ClientSize.Width && bt.Bottom <= ClientSize.Height;
                    if (bt.Right > worst) worst = bt.Right;
                    b.AppendLine("按钮         : " + bt.Text.PadRight(12) + " " + bt.Left + "," + bt.Top
                                 + " 右边缘 " + bt.Right + (inside ? "  ✓在窗口内" : "  ✗被裁掉"));
                }
                b.AppendLine("按钮行最大右边缘: " + worst + "（必须 <= " + ClientSize.Width + "）");
                b.AppendLine("页脚         : " + foot.Left + "," + foot.Top
                             + (foot.Top >= cardAdv.Bottom ? "  ✓在结论卡下方" : "  ✗压在结论卡上"));
                b.AppendLine("正文底 / 页脚顶: " + cardAdv.Bottom + " / " + foot.Top
                             + (foot.Top >= cardAdv.Bottom ? "  ✓不重叠" : "  ✗重叠，最后一行会被盖住"));
                // 卡片贴不贴正文：以前固定 280 像素，两行字的结论下面会空一大片
                int slack = cardAdv.Bottom - (cardAdv.Top + lAdvBody.Bottom);
                b.AppendLine("卡片底部空白 : " + slack + " px（应 <= 20，否则就是没跟着正文缩）");
            }
            catch (Exception ex) { b.AppendLine("排版自检失败: " + ex.Message); }
            return b.ToString();
        }

        private static string Shorten(string s, int maxLines)
        {
            if (s == null) return "";
            string[] lines = s.Replace("\r\n", "\n").Split('\n');
            if (lines.Length <= maxLines) return s;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLines; i++) sb.AppendLine(lines[i]);
            sb.Append("…… 完整步骤点下面的「详细报告」");
            return sb.ToString();
        }

        // 「设备驱动」那一行只放一句结论；设备清单留给下面的结论卡，否则一行放不下会串行
        private static string ShortDevText(string dev, int bad)
        {
            if (bad <= 0) return dev == null ? "没有发现问题的设备" : dev;
            string s = "有 " + bad + " 个驱动有问题（看下面）";
            return s;
        }

        private static string GB(long mb)
        {
            return (mb / 1024.0).ToString("0.0", CultureInfo.InvariantCulture) + " GB";
        }

        private static string F1(double v, string unit)
        {
            return v < 0 ? "N/A" : Math.Round(v, 1).ToString(CultureInfo.InvariantCulture) + unit;
        }

        private void SetCard(int i, string value, string sub, Color color, double ratio, Color barColor)
        {
            cardValue[i].Text = value;
            cardValue[i].ForeColor = color;
            cardSub[i].Text = sub;
            cardBar[i].Ratio = ratio;
            cardBar[i].Fill = barColor;
            card[i].Accent = barColor;
            card[i].Invalidate();
            cardBar[i].Invalidate();
        }

        private void Apply(UiData d)
        {
            latest = d;
            try
            {
                // ---------- 结论与配色 ----------
                bool hard = d.NeedHelp;
                bool soft = !hard && (d.BadDevices > 0 || d.RebootPending);
                Color tone = hard ? Red : (soft ? Amber : Green);
                dot.Dot = tone;
                dot.Invalidate();

                lSub.Text = (hard ? "检测到" + d.StressKind + "压力，自动处理没能解决 —— 下面给了办法"
                            : soft ? "基本正常，有几项值得留意（下面已标出）"
                            : "一切正常，后台正在盯着")
                           + "    ·    更新于 " + d.Time
                           + "    ·    已运行 " + d.Uptime + " 小时"
                           + "    ·    " + d.RunState
                           + "    ·    " + d.Perm;

                // ---------- 卡 1：可用内存 ----------
                double usedPct = d.TotalMB > 0 ? 100.0 * (d.TotalMB - d.AvailMB) / d.TotalMB : 0;
                Color mCol = usedPct >= 88 ? Red : (usedPct >= 75 ? Amber : Green);
                SetCard(0, GB(d.AvailMB),
                        "共 " + GB(d.TotalMB) + " · 已用 " + usedPct.ToString("0.0", CultureInfo.InvariantCulture) + "%",
                        mCol, usedPct / 100.0, mCol);

                // ---------- 卡 2：提交内存 ----------
                double cPct = d.CommitPct;
                Color cCol = cPct >= 90 ? Red : (cPct >= d.CommitThreshold ? Amber : Green);
                SetCard(1, cPct.ToString("0", CultureInfo.InvariantCulture) + "%",
                        GB(d.CommitMB) + " / " + GB(d.CommitLimitMB) + " · 阈值 " + d.CommitThreshold + "%",
                        cCol, cPct / 100.0, cCol);

                // ---------- 卡 3：换页压力 ----------
                double hf = d.HardFaultsPerSec;
                Color hCol = hf < 0 ? Gray : (hf >= d.HardFaultThreshold ? Red : (hf >= d.HardFaultThreshold / 4.0 ? Amber : Green));
                SetCard(2, hf < 0 ? "N/A" : Math.Round(hf).ToString(CultureInfo.InvariantCulture) + " /秒",
                        "DPC " + F1(d.DpcPct, "%") + " · 中断 " + F1(d.InterruptPct, "%"),
                        hCol, hf < 0 ? 0 : Math.Min(1.0, hf / Math.Max(1.0, d.HardFaultThreshold)), hCol);

                // ---------- 卡 4：系统负载 ----------
                double cpu = d.CpuPct, dsk = d.DiskBusyPct;
                Color lCol = (cpu >= 95 || dsk >= 95) ? Red : ((cpu >= 80 || dsk >= 80) ? Amber : Green);
                SetCard(3, cpu < 0 ? "N/A" : "CPU " + Math.Round(cpu).ToString(CultureInfo.InvariantCulture) + "%",
                        "磁盘 " + F1(dsk, "%") + " · 队列 " + F1(d.DiskQueue, "") + " · " + F1(d.DiskMBps, " MB/s"),
                        lCol, cpu < 0 ? 0 : cpu / 100.0, lCol);

                // ---------- 系统设置 ----------
                sysV[0].Text = d.FastStartupOff ? "已关闭 ✓（关机才会真正清理内核状态）" : "开启中 —— 建议关闭";
                sysV[0].ForeColor = d.FastStartupOff ? Green : Amber;
                sysV[1].Text = d.TdrText;
                sysV[1].ForeColor = d.TdrOk ? Green : Amber;
                sysV[2].Text = d.AutoStart ? "已启用 ✓" : "未启用";
                sysV[2].ForeColor = d.AutoStart ? Green : Gray;
                sysV[3].Text = ShortDevText(d.DevText, d.BadDevices);
                sysV[3].ForeColor = d.BadDevices > 0 ? Amber : Green;
                sysV[4].Text = d.RebootPending ? "有改动等着重启生效" : "无";
                sysV[4].ForeColor = d.RebootPending ? Amber : Green;

                // ---------- 最近情况 ----------
                evtV[0].Text = d.Tdr4101 < 0 ? "N/A" : d.Tdr4101 + " 次" + (d.Tdr4101 > 0 ? "（显卡驱动恢复过）" : "");
                evtV[0].ForeColor = d.Tdr4101 > 0 ? Amber : Green;
                evtV[1].Text = d.Whea < 0 ? "N/A" : d.Whea + " 次";
                evtV[1].ForeColor = d.Whea > 0 ? Amber : Green;
                evtV[2].Text = Show(d.StandbyMB) + " MB / " + Show(d.ModifiedMB) + " MB";
                evtV[2].ForeColor = Ink;
                evtV[3].Text = d.CompressionMB + " MB（阈值 " + app.Cfg.CompressionThresholdMB + " MB）";
                evtV[3].ForeColor = d.CompressionMB >= app.Cfg.CompressionThresholdMB ? Amber : Ink;
                evtV[4].Text = d.Procs + " / " + d.Threads + " / " + d.Handles;
                evtV[4].ForeColor = Ink;

                // ---------- 结论卡 ----------
                if (d.NeedHelp)
                {
                    lAdvHead.Text = "需要你处理一下（自动处理没能解决）";
                    lAdvHead.ForeColor = Red;
                    cardAdv.Accent = Red;
                    lAdvBody.ForeColor = Color.FromArgb(58, 64, 74);
                    lAdvBody.Text = Shorten(d.Advice, 9);
                }
                else if (d.BadDevices > 0 || d.RebootPending)
                {
                    lAdvHead.Text = d.BadDevices > 0 ? "建议处理（不影响日常使用，但和卡顿有关）" : "建议处理";
                    lAdvHead.ForeColor = Amber;
                    cardAdv.Accent = Amber;
                    lAdvBody.ForeColor = Color.FromArgb(58, 64, 74);
                    lAdvBody.Text = Shorten((d.BadDevices > 0 ? d.DeviceAdvice : ""), 10)
                                  + (d.RebootPending ? "\n另外：有改动要重启后才生效，建议找个方便的时候重启一次。" : "");
                }
                else
                {
                    lAdvHead.Text = "一切正常，不需要你做什么";
                    lAdvHead.ForeColor = Green;
                    cardAdv.Accent = Green;
                    lAdvBody.ForeColor = Color.FromArgb(90, 96, 106);
                    lAdvBody.Text = "程序只整理「没在用」的后台进程，你正在用的 firefox / node / 虚拟机不会被碰，"
                                  + "也不需要你去关它们。\n"
                                  + "增长追踪: " + d.LeakText + "\n"
                                  + "最近整理: " + d.LastTrim
                                  + (d.PerfError.Length > 0 ? "\n注意: " + d.PerfError : "");
                }
                // ★ 结论正文的行数每次都不一样（增长追踪那行尤其长），
                //   固定高度一定会出现「最后一行被页脚盖住」。这里按实际像素量一次。
                FitAdvBody();
                cardAdv.Invalidate();

                foot.Text = "配置目录: " + Config.Dir
                          + "    （要看完整数据就点「详细报告」）";
            }
            catch (Exception ex)
            {
                try { Log.Write("界面回填失败: " + ex.Message); } catch { }
            }
        }

        private static string Show(long v) { return v < 0 ? "N/A" : v.ToString(); }

        // 纯文本报告退居二线：只在用户主动点「详细报告」时才打开
        private void ShowDetail()
        {
            string t = null;
            try { t = app.BuildReport(); } catch (Exception ex) { t = "生成报告失败: " + ex.Message; }
            if (t == null || t.Length == 0)
                t = (latest != null && latest.FullText != null) ? latest.FullText : "暂无数据";
            using (DevForm f = new DevForm(t, "SmoothWin 详细报告")) { f.ShowDialog(this); }
        }

        // 自检用：把卡片上的实际文字倒出来，确认界面确实被填上了数据。
        // 以前只能靠「窗口是不是未响应」来判断，太粗糙。
        public string DumpForTest()
        {
            StringBuilder b = new StringBuilder();
            try
            {
                b.AppendLine("标题     : " + lHead.Text);
                b.AppendLine("副标题   : " + lSub.Text);
                b.AppendLine("状态圆点 : " + dot.Dot.ToString());
                for (int i = 0; i < 4; i++)
                    b.AppendLine("指标卡" + (i + 1) + " : " + cardTitle[i].Text + " = " + cardValue[i].Text
                                + "   [" + cardSub[i].Text + "]   进度=" + cardBar[i].Ratio.ToString("0.00", CultureInfo.InvariantCulture));
                for (int i = 0; i < 5; i++)
                    b.AppendLine("系统设置 : " + sysK[i].Text + " = " + sysV[i].Text);
                for (int i = 0; i < 5; i++)
                    b.AppendLine("最近情况 : " + evtK[i].Text + " = " + evtV[i].Text);
                b.AppendLine("结论标题 : " + lAdvHead.Text);
                b.AppendLine("结论正文 : " + lAdvBody.Text.Replace("\n", " | "));
                b.AppendLine("页脚     : " + foot.Text);
            }
            catch (Exception ex) { b.AppendLine("导出失败: " + ex.Message); }
            return b.ToString();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                return;
            }
            try { tick.Stop(); } catch { }
            base.OnFormClosing(e);
        }
    }

    // ==================== 设备检查窗口 ====================
    // 只读、不自动刷新：内容是「一次性检查结果」，不需要每秒重画，
    // 也正好避开「刷新把滚动条拽回顶部」那类问题。
    internal class DevForm : Form
    {
        private TextBox box;
        private bool copied;

        public DevForm(string text) : this(text, "SmoothWin 设备检查") { }

        public DevForm(string text, string title)
        {
            Text = title;
            ClientSize = new Size(720, 470);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = true;
            ShowInTaskbar = true;

            box = new TextBox();
            box.Multiline = true;
            box.ReadOnly = true;
            box.ScrollBars = ScrollBars.Both;
            box.WordWrap = false;
            box.Font = new Font("Consolas", 9.5f);
            box.BackColor = Color.FromArgb(24, 24, 28);
            box.ForeColor = Color.FromArgb(220, 220, 220);
            box.BorderStyle = BorderStyle.None;
            // 打开这个窗口时 WinForms 会把焦点给第一个控件，只读文本框一拿到焦点
            // 就整段反白 —— 用户看到的就是「一点开文字全被选中了」。三处一起治：
            // TabStop=false 不让它抢焦点，HideSelection=true 失焦时不画选中，
            // SelectionLength 归零把已经产生的选中抹掉。
            box.TabStop = false;
            box.HideSelection = true;
            box.SetBounds(10, 10, ClientSize.Width - 20, ClientSize.Height - 60);
            box.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            box.Text = text;
            box.SelectionStart = 0;
            box.SelectionLength = 0;
            Controls.Add(box);

            Button bCopy = new Button();
            bCopy.Text = "复制全部";
            bCopy.SetBounds(10, ClientSize.Height - 40, 100, 28);
            bCopy.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bCopy.Click += delegate
            {
                try { Clipboard.SetText(box.Text); copied = true; bCopy.Text = "已复制"; }
                catch { }
            };
            Controls.Add(bCopy);

            Button bClose = new Button();
            bClose.Text = "关闭";
            bClose.SetBounds(ClientSize.Width - 110, ClientSize.Height - 40, 100, 28);
            bClose.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
            bClose.Click += delegate { Close(); };
            Controls.Add(bClose);

            // 这里原来有一个「去下载 AMD 驱动」按钮：留着它就等于把程序绑死在
            // 这一台机器、这一个厂商上。用户要的是通用工具 —— 只说明问题，
            // 由用户自己按机型去装驱动。留「打开设备管理器」就够定位了。
            Button bDevMgr = new Button();
            bDevMgr.Text = "打开设备管理器";
            bDevMgr.SetBounds(116, ClientSize.Height - 40, 130, 28);
            bDevMgr.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bDevMgr.Click += delegate
            {
                try { Process.Start(new ProcessStartInfo("devmgmt.msc") { UseShellExecute = true }); }
                catch (Exception ex) { MessageBox.Show("打不开设备管理器: " + ex.Message); }
            };
            Controls.Add(bDevMgr);

            Button bRescan = new Button();
            bRescan.Text = "重新检查";
            bRescan.SetBounds(252, ClientSize.Height - 40, 100, 28);
            bRescan.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            bRescan.Click += delegate
            {
                try
                {
                    List<BadDevice> all = Devices.Scan();
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine("SmoothWin 设备检查   " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                    sb.AppendLine();
                    int hit = 0;
                    foreach (BadDevice d in all) if (Devices.IsLikelyCause(d)) hit++;
                    if (hit == 0) sb.AppendLine("没有发现会影响性能的设备问题。").AppendLine().AppendLine("（未接入的 U 盘、没连上的蓝牙耳机这类不算问题，已自动忽略）");
                    else
                    {
                        sb.AppendLine(Devices.Advice()).AppendLine();
                        sb.AppendLine("--- 全部异常设备 ---");
                        foreach (BadDevice d in all)
                            sb.AppendLine((Devices.IsLikelyCause(d) ? "[影响] " : "[忽略] ") + d.Display + "  ——  " + d.MeaningShort).AppendLine("        " + d.Instance);
                    }
                    sb.AppendLine();
                    sb.AppendLine("--- 挂起重启 ---");
                    sb.AppendLine(Reg.RebootPending() ? "有改动要重启后才生效。重启一次能把这些改动落地。" : "没有挂起的重启项。");
                    sb.AppendLine("已连续运行 " + (Sample.Take().UptimeHours / 24).ToString("0.0") + " 天");
                    box.Text = sb.ToString();
                    box.SelectionStart = 0; box.SelectionLength = 0;
                    bCopy.Text = "复制全部"; copied = false;
                }
                catch (Exception ex) { box.Text = "检查失败: " + ex.Message; }
            };
            Controls.Add(bRescan);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            // 再兜一次：某些主题/输入法会在窗口真正显示后重新把只读框整段选中。
            try { box.SelectionStart = 0; box.SelectionLength = 0; } catch { }
        }

        // 自检用：确认打开窗口时文本框没有被整段选中（用户反馈「点开文字就被选中了」）。
        internal string SelectionForTest()
        {
            return "SelectionStart=" + box.SelectionStart + "  SelectionLength=" + box.SelectionLength
                   + "  TabStop=" + box.TabStop + "  HideSelection=" + box.HideSelection
                   + "  焦点在=" + (ActiveControl == null ? "（无）" : ActiveControl.GetType().Name)
                   + "  文本框有焦点=" + box.Focused
                   + "  文本长度=" + box.TextLength;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // 用户复制完就关，别再弹「是否保存」之类的干扰
            if (copied) { }
            base.OnFormClosing(e);
        }
    }

    // ==================== 设置窗口 ====================
    internal class SettingsForm : Form
    {
        private NumericUpDown nCommit, nComp, nCool, nMin, nSample, nPeriodic, nTrimCool;
        private CheckBox cAuto, cWarn, cStart, cIdleOnly, cFlush;
        // 「自动」勾选框：勾上 = 该项按本机物理内存算，取消 = 固定成你填的数字。
        // 受容量影响的三个项各配一个，这样同一份程序在 8GB 笔记本和 64GB 台机上
        // 都能给出合适的阈值，而不是把一台机器的数字带到另一台。
        private CheckBox cAutoCommit, cAutoComp, cAutoMin;
        // 增长提醒的忽略名单 / 自动静音次数（用户对 node 那类开发工具的核心诉求）
        private TextBox tbIgnore;
        private NumericUpDown nMuteAfter;
        private TrayApp app;

        public SettingsForm(TrayApp owner)
        {
            app = owner;
            Text = "SmoothWin 设置";
            ClientSize = new Size(480, 540);   // 底部多了一行忽略名单 + 一行静音次数
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false; MinimizeBox = false;
            Config c = owner.Cfg;

            int y = 16;
            nCommit = Num("提交内存超过 (%) 时自动整理:", y, c.CommitThresholdPct, 30, 99);
            cAutoCommit = Auto("自动", y, c.AutoTune && !c.UserSetCommit); y += 32;
            nComp = Num("内存压缩超过 (MB) 时自动整理:", y, c.CompressionThresholdMB, 0, 65536);
            cAutoComp = Auto("自动", y, c.AutoTune && !c.UserSetComp); y += 32;
            nCool = Num("两次自动整理最小间隔 (秒):", y, c.CooldownSeconds, 30, 86400); y += 32;
            nMin = Num("只整理工作集大于 (MB) 的进程:", y, c.MinTrimMB, 10, 8192);
            cAutoMin = Auto("自动", y, c.AutoTune && !c.UserSetMinTrim); y += 32;
            nSample = Num("状态采样间隔 (秒):", y, c.SampleSeconds, 1, 600); y += 32;
            nPeriodic = Num("定时维护间隔 (分钟，0=关闭):", y, c.PeriodicTrimMinutes, 0, 1440); y += 38;

            cAuto = Chk("启用自动整理", y, c.AutoTrim); y += 26;
            cIdleOnly = Chk("只整理「没在用」的进程（正在用/正在跑任务的一律跳过）", y, c.TrimIdleOnly); y += 26;
            nTrimCool = Num("同一进程两次整理最小间隔 (秒):", y, c.TrimCooldownSeconds, 0, 86400); y += 32;
            cFlush = Chk("深度整理时强制把已修改页面写盘（会制造读盘高峰，建议不勾）", y, c.AggressiveFlushModified); y += 26;
            cWarn = Chk("检测到显卡驱动崩溃(事件4101)时气泡提醒", y, c.WarnOnTdr); y += 26;
            cStart = Chk("开机自动启动（开机/登录时启动，不是「退出后又自己回来」）", y, Reg.IsAutoStartEnabled()); y += 34;

            // ★ 「增长提醒」的忽略名单。有些程序「一直在变大」是它本来的工作方式
            //   （node / 编译器 / 虚拟机 / 浏览器），提醒用户去重启它毫无意义 ——
            //   用户原话：「node 是我开发工具，我需要开很多服务，提示我这个也没用」。
            Label lIgnore = new Label();
            lIgnore.Text = "增长提醒忽略名单（进程名，逗号分隔，留空 = 都提醒）:";
            lIgnore.SetBounds(16, y + 3, 448, 20);
            Controls.Add(lIgnore); y += 24;
            tbIgnore = new TextBox();
            tbIgnore.SetBounds(16, y, 448, 24);
            tbIgnore.Text = c.LeakIgnoreNames;
            Controls.Add(tbIgnore); y += 32;
            nMuteAfter = Num("同一程序提醒几次后自动静音（0 = 不静音）:", y, c.LeakMuteAfter, 0, 99); y += 32;

            // 通用性说明：同一份程序在不同内存的机器上要给出不同阈值
            long totalMB = TotalMB();
            Label hint = new Label();
            hint.Text = "「自动」= 按本机物理内存自动计算（本机 " + (totalMB > 0 ? totalMB + " MB" : "未知") + "），"
                      + "换机器或加内存后会自动重算；取消勾选即固定为你填的数字。";
            hint.SetBounds(16, y, 448, 32);
            hint.ForeColor = SystemColors.GrayText;
            Controls.Add(hint); y += 38;

            Button ok = new Button(); ok.Text = "保存"; ok.SetBounds(280, y, 80, 28);
            ok.Click += delegate { Save(); Close(); };
            Button cancel = new Button(); cancel.Text = "取消"; cancel.SetBounds(370, y, 80, 28);
            cancel.Click += delegate { Close(); };
            Controls.Add(ok); Controls.Add(cancel);

            SyncAuto();   // 初始状态：勾上的项数字框变灰并显示当前算出来的值
        }

        private NumericUpDown Num(string label, int y, int val, int min, int max)
        {
            Label l = new Label(); l.Text = label; l.SetBounds(16, y + 3, 250, 20); Controls.Add(l);
            NumericUpDown n = new NumericUpDown();
            n.SetBounds(272, y, 100, 24); n.Minimum = min; n.Maximum = max; n.Value = Math.Max(min, Math.Min(max, val));
            Controls.Add(n);
            return n;
        }
        private CheckBox Chk(string label, int y, bool val)
        {
            // 宽度给足：中文标签在 340px 下会折行，折行后又和第二行的控件叠在一起。
            CheckBox c = new CheckBox(); c.Text = label; c.SetBounds(16, y, 448, 22); c.Checked = val; Controls.Add(c);
            return c;
        }

        // 受物理内存容量影响的项，右侧配一个「自动」勾选框
        private CheckBox Auto(string label, int y, bool val)
        {
            CheckBox c = new CheckBox();
            c.Text = label; c.SetBounds(380, y + 3, 70, 22); c.Checked = val;
            c.CheckedChanged += delegate { SyncAuto(); };
            Controls.Add(c);
            return c;
        }

        // 本机物理内存（MB）：优先用启动时自适应记下的值，没有就现采一次
        private long TotalMB()
        {
            try { if (app.Cfg.TotalPhysMB > 0) return app.Cfg.TotalPhysMB; } catch { }
            try { return Sample.Take().TotalMB; } catch { }
            return 0;
        }

        // 「自动」状态的观感：只读 + 灰底，数值仍然清晰可读
        private static void SetAutoLook(NumericUpDown n, bool isAuto)
        {
            n.ReadOnly = isAuto;
            n.BackColor = isAuto ? SystemColors.Control : SystemColors.Window;
            // 文字一律用正常色：灰底 + 灰字会让「当前生效值」几乎看不清，
            // 而灰底本身已经足够表达「这项是自动算的、不用你填」。
            n.ForeColor = SystemColors.WindowText;
        }

        private static void SetNum(NumericUpDown n, long v)
        {
            if (v < (long)n.Minimum) v = (long)n.Minimum;
            if (v > (long)n.Maximum) v = (long)n.Maximum;
            n.Value = v;
        }

        // 勾上「自动」的项：数字框变灰并显示当前算出来的值（只作预览）；
        // 取消勾选则恢复可编辑，值保持不动，等于「就用这个数」。
        private void SyncAuto()
        {
            long t = TotalMB();
            // 用 ReadOnly + 灰底表示「这项是自动的」，而不是 Enabled=false：
            // 禁用状态下数字会被系统画成浅灰，几乎看不清当前生效值是多少。
            SetAutoLook(nCommit, cAutoCommit.Checked);
            SetAutoLook(nComp, cAutoComp.Checked);
            SetAutoLook(nMin, cAutoMin.Checked);
            if (t > 0)
            {
                if (cAutoCommit.Checked) SetNum(nCommit, Config.TunedCommitPct(t));
                if (cAutoComp.Checked) SetNum(nComp, Config.TunedCompressionMB(t));
                if (cAutoMin.Checked) SetNum(nMin, Config.TunedMinTrimMB(t));
            }
        }

        // ---- 以下三个只给命令行自检（--settingshot）用 ----
        internal void SetAutoForTest(bool commit, bool comp, bool minTrim)
        {
            cAutoCommit.Checked = commit; cAutoComp.Checked = comp; cAutoMin.Checked = minTrim;
            SyncAuto();
        }
        internal string DumpForTest()
        {
            return "自动勾选: 提交=" + cAutoCommit.Checked + " 压缩=" + cAutoComp.Checked + " 下限=" + cAutoMin.Checked
                 + "  |  可手填(非只读): 提交=" + (!nCommit.ReadOnly) + " 压缩=" + (!nComp.ReadOnly) + " 下限=" + (!nMin.ReadOnly)
                 + "  |  显示值: " + nCommit.Value + "% / " + nComp.Value + "MB / " + nMin.Value + "MB";
        }
        internal void SaveForTest() { Save(); }

        private void Save()
        {
            Config c = app.Cfg;
            // 「自动」勾选框 → UserSet 标志：勾上就写 auto（换机器/加内存自动重算），
            // 取消就固定成当前框里的数字。
            c.UserSetCommit = !cAutoCommit.Checked;
            c.UserSetComp = !cAutoComp.Checked;
            c.UserSetMinTrim = !cAutoMin.Checked;
            c.AutoTune = cAutoCommit.Checked || cAutoComp.Checked || cAutoMin.Checked;
            c.CommitThresholdPct = (int)nCommit.Value;
            c.CompressionThresholdMB = (int)nComp.Value;
            c.CooldownSeconds = (int)nCool.Value;
            c.MinTrimMB = (int)nMin.Value;
            c.SampleSeconds = (int)nSample.Value;
            c.PeriodicTrimMinutes = (int)nPeriodic.Value;
            c.AutoTrim = cAuto.Checked;
            c.TrimIdleOnly = cIdleOnly.Checked;
            c.TrimCooldownSeconds = (int)nTrimCool.Value;
            c.AggressiveFlushModified = cFlush.Checked;
            c.WarnOnTdr = cWarn.Checked;
            c.LeakIgnoreNames = (tbIgnore.Text ?? "").Trim();
            c.LeakMuteAfter = (int)nMuteAfter.Value;
            c.Save();
            Reg.SetAutoStart(cStart.Checked);
            app.Reconfigure();
            Log.Write("设置已保存");
        }
    }

    // ==================== 托盘主程序 ====================
    internal class TrayApp : ApplicationContext
    {
        public Config Cfg;
        public Icon AppIcon;
        private Icon icoOk, icoWarn, icoBad, icoOff;
        private NotifyIcon ni;
        private System.Windows.Forms.Timer timer;
        private DateTime lastTrim = DateTime.MinValue;
        private DateTime lastHistory = DateTime.MinValue;
        private DateTime lastPeriodic = DateTime.MinValue;
        private bool paused;
        private Sample last;
        private string lastTrimText = "尚未整理";
        private StatusForm win;
        private DateTime lastTdrCheck = DateTime.MinValue;
        private DateTime lastSeenTdr = DateTime.MinValue;
        private bool disposed;
        // 通知气泡必须在 UI 线程上弹。状态窗口的刷新跑在后台线程里，
        // 顺手做的设备检查可能触发提醒 —— 用它把调用切回 UI 线程。
        private SynchronizationContext uiCtx;
        // ---- 通用化新增：换页压力告警 + 进程增长(疑似泄漏)追踪 ----
        // 注：这里曾经有一个「15 分钟内不重复提醒」的时间戳字段，但它和 stressNotified
        // 是同一件事的两种写法；保留一个状态机更不容易出错，故删掉。

        // 持续压力自愈状态机
        private int stressStreak, stressFixTries;
        private bool stressNotified;
        // 「因为你自己的程序在占资源 / 你正在用电脑，所以这一轮不打扰」的标记。
        // 只有它存在，跳过分支才不会在下一个采样周期（几秒后）立刻又弹一次——
        // 实测日志 23:28:54 写了「不打扰」，23:28:55 仍然写了「需要人工处理」并弹了气泡。
        // 语义与 stressNotified 不同：stressNotified 表示「真的弹过气泡」。
        private bool stressSkipped;
        private string stressKind = "";
        private DateTime lastStressFix = DateTime.MinValue;
        // 上一次「真的弹了气泡」的时间。同类压力在这个间隔内不再重复提醒——
        // 没有它时压力一解除 stressNotified 就复位，几十秒后又能弹一次。
        private DateTime lastStressWarn = DateTime.MinValue;
        // 「因为你在用自己的程序，所以不打扰」的日志节流（同类最多 10 分钟一条，避免刷屏）
        private DateTime lastUserProgSkipLog = DateTime.MinValue;
        // 「你正在用电脑，暂不打扰」的日志节流，同上
        private DateTime lastIdleSkipLog = DateTime.MinValue;
        public string AdviceText = "暂无需处理。出现持续压力且自动处理无效时，这里会给出具体建议。";
        private DateTime lastLeakScan = DateTime.MinValue;
        public string LeakText = "尚未开始追踪（运行满一个采样周期后出现）";
        public string StressText = "未采样";
        private string lastLeakWarnKey = "";
        private DateTime lastLeakWarnTime = DateTime.MinValue;
        // 「增长追踪」连续确认计数：同一个程序连续 N 次采样都超标才提醒。
        // node / firefox / qemu 这类程序正常跑起来就在长，单次超标说明不了问题。
        private int leakStreak;
        private string leakStreakKey = "";
        // 同一个程序累计提醒过几次（跨会话保留在 ini 的忽略名单里，这里只管本次运行）。
        private Dictionary<string, int> leakSeen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        // 用户点「别再提醒这个程序」时，把名字放到这里，由 CheckLeak 落盘。
        // 不能直接在气球回调里写 ini：那个回调跑在 NotifyIcon 的消息线程上。
        private volatile string pendingLeakIgnore = null;
        private DateTime pendingLeakIgnoreTime = DateTime.MinValue;
        // ---- 系统层检查：有问题的设备驱动、挂着重启没做 ----
        private string DevText = "尚未检查";
        private string startupText = null;
        private DateTime lastStartupScan = DateTime.MinValue;
        private DateTime lastDevCheck = DateTime.MinValue;
        private DateTime lastRebootWarn = DateTime.MinValue;
        public bool RebootPendingFlag;
        public int BadDeviceCount;

        // 统一的配置装载：先读用户配置，再按本机物理内存套用通用自适应阈值。
        // 用户显式在配置文件里写过的项不会被覆盖。
        // 注意：命令行模式（--trim / --report）也必须走这里，否则计划任务跑的是
        // 「配置文件里的原始数字」而不是自适应后的值 —— 在别的机器上就是两套阈值。
        internal static Config LoadConfig()
        {
            Config c = Config.Load();
            try
            {
                Sample s0 = Sample.Take();
                c.ApplyAutoTune(s0.TotalMB);
            }
            catch { }
            return c;
        }

        // 命令行模式用的轻量构造：不创建托盘图标、不启动定时器
        public TrayApp(bool cliOnly)
        {
            Cfg = LoadConfig();
            last = Sample.Take();
        }

        public void ShutdownForCli() { }

        // 心跳停滞判定：进程还在、但 heartbeat.log 已经很久没被写过，说明消息循环卡死
        // （托盘还占着单实例互斥体，看门狗拉不起来，必须由新实例把它接管掉）。
        // 阈值取 max(180 秒, 心跳周期×4)，避免采样偶发变慢时误杀自己。
        // 心跳「活体年龄」：最后一条 alive 行距今多少秒；没有可用记录时返回 -1。
        // 只认 alive 行，不看文件修改时间——看门狗每 5 分钟拉起的临时实例一启动
        // 就会往心跳文件里写「启动 pid=…」，会把文件时间戳刷成刚刚，
        // 于是「假死的旧实例」永远检测不出来（实测踩过这个坑）。
        internal static double HeartbeatAgeSeconds()
        {
            try
            {
                string p = Path.Combine(Config.Dir, "heartbeat.log");
                if (!File.Exists(p)) return -1;
                string last = null;
                try
                {
                    string[] lines = File.ReadAllLines(p);
                    for (int i = lines.Length - 1; i >= 0; i--)
                        if (lines[i].IndexOf(" alive ", StringComparison.Ordinal) > 0) { last = lines[i]; break; }
                }
                catch { }
                if (last == null || last.Length < 19) return -1;
                DateTime t;
                if (!DateTime.TryParseExact(last.Substring(0, 19), "yyyy-MM-dd HH:mm:ss",
                        CultureInfo.InvariantCulture, DateTimeStyles.None, out t)) return -1;
                return (DateTime.Now - t).TotalSeconds;
            }
            catch { return -1; }
        }

        internal static bool IsHung()
        {
            try
            {
                int every = Math.Max(10, Config.Load().HeartbeatSeconds);
                double limit = Math.Max(180.0, every * 4.0);
                double age = HeartbeatAgeSeconds();
                return age >= 0 && age > limit;
            }
            catch { return false; }
        }

        // 杀掉卡死的旧实例。只在前一步已经确认「最后一条心跳属于别人、而且早就停了」时调用，
        // 这里再逐进程确认一次「不是我自己」，避免把自己杀掉。
        internal static void KillHung()
        {
            try
            {
                int me = Process.GetCurrentProcess().Id;
                foreach (Process p in Process.GetProcessesByName("SmoothWinTray"))
                {
                    try
                    {
                        if (p.Id != me)
                        {
                            Log.Heartbeat("接管：结束假死实例 pid=" + p.Id);
                            p.Kill();
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
                Thread.Sleep(2000);
            }
            catch { }
        }

        // 消息循环「停摆」自愈：心跳线程独立于 UI 线程。
        // 若 UI 线程卡死（心跳不再更新）超过阈值，这个线程就把单实例互斥体交出去
        // 然后退出，让计划任务的下一个触发点拉起干净的新实例接管。
        // 这是唯一能覆盖「进程没死、但界面和定时器全停了」这种静默故障的办法。
        //
        // ★ 为什么这里必须「先交出互斥体」而不是像以前那样直接 Environment.Exit：
        //   Environment.Exit 不会释放命名互斥体 —— 这个进程仍然是互斥体的持有者，
        //   看门狗拉起来的新实例创建互斥体时拿到的是「已存在」，于是判定「已有实例在运行」
        //   直接静默退出。结果就是：旧实例退出了、新实例进不来，托盘彻底消失，
        //   要等到用户下次登录才恢复。手动退出/假死自愈时都会走这里，所以统一改成交出。
        private volatile bool watchdogOff;    // 手动退出后置位：停摆看门狗不再自我退出
        private volatile bool tailCheckOff;   // 手动退出后置位：心跳尾巴自检不再判定异常

        private void StartStallWatchdog()
        {
            Thread t = new Thread(delegate ()
            {
                while (!disposed && !watchdogOff)
                {
                    try
                    {
                        int every = Math.Max(10, Cfg.HeartbeatSeconds);
                        double limit = Math.Max(180.0, every * 6.0);
                        Thread.Sleep((int)Math.Max(20000, limit * 1000 / 3));
                        if (disposed) break;
                        double age = HeartbeatAgeSeconds();
                        if (age >= 0 && age > limit)
                        {
                            Log.Write("消息循环停摆 " + Math.Round(age) + " 秒（心跳不再更新），交出单实例锁并退出，让看门狗接管");
                            Log.Heartbeat("停摆自愈退出 pid=" + Process.GetCurrentProcess().Id + " 停滞=" + Math.Round(age) + "秒");
                            Program.ReleaseSingleInstance();
                            Environment.Exit(0);
                        }
                    }
                    catch { }
                }
            });
            t.IsBackground = true;
            t.Name = "stall-watchdog";
            try { t.Start(); } catch { }
        }

        public TrayApp()
        {
            Cfg = LoadConfig();
            icoOk = MakeIcon(Color.FromArgb(46, 160, 67));
            icoWarn = MakeIcon(Color.FromArgb(210, 153, 34));
            icoBad = MakeIcon(Color.FromArgb(200, 60, 60));
            icoOff = MakeIcon(Color.FromArgb(120, 120, 120));
            AppIcon = icoOk;

            ni = new NotifyIcon();
            ni.Icon = icoOk;
            ni.Text = "SmoothWin 常驻监控";   // 托盘悬停文字（≤63 字符）
            ni.Visible = true;
            ni.DoubleClick += delegate { ShowWindow(); };
            ni.MouseClick += delegate (object s2, MouseEventArgs e2) { if (e2.Button == MouseButtons.Left) ShowWindow(); };
            // 点一下气泡就进状态窗口看完整建议——通知里塞不下长文本，但点进来就有全文。
            // 如果刚弹的是「某程序一直在变大」，顺手问一句要不要以后别再提醒它。
            ni.BalloonTipClicked += delegate { OnBalloonClicked(); };
            ni.ContextMenuStrip = BuildMenu();

            try { lastSeenTdr = Events.LastTdrTime(); } catch { }
            Log.Write("SmoothWinTray 启动  管理员=" + Trimmer.IsAdmin + "  自动整理=" + Cfg.AutoTrim);

            try { SystemEvents.PowerModeChanged += OnPower; } catch { }

            timer = new System.Windows.Forms.Timer();
            timer.Interval = Math.Max(1, Cfg.SampleSeconds) * 1000;
            // 后台线程要弹气泡就得能切回 UI 线程。Application.Run 之前
            // SynchronizationContext.Current 往往是 null，显式装一个。
            try
            {
                if (SynchronizationContext.Current == null)
                    SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
                uiCtx = SynchronizationContext.Current;
            }
            catch { }
            timer.Tick += delegate { Tick(); };
            timer.Start();
            Tick();
            StartStallWatchdog();
            StartExitWatcher();

            // 自动化实测（--testdir）专用：N 秒后自己点一次「退出」。
            // 走的是 ExitApp("…", true) —— 和托盘菜单「退出」完全同一条路径，
            // 这样实测验证的是真实行为，而不是测试专用分支。
            if (Config.TestMode && Config.TestExitAfterSec > 0)
            {
                int after = Config.TestExitAfterSec;
                Log.Write("测试模式：将在 " + after + " 秒后自动执行「手动退出」（与托盘菜单同一路径）");
                Thread t2 = new Thread(delegate ()
                {
                    try
                    {
                        Thread.Sleep(after * 1000);
                        Log.Write("测试模式：现在执行手动退出");
                        try { uiCtx.Post(delegate { ExitApp("测试模式自动退出", true); }, null); }
                        catch { ExitApp("测试模式自动退出", true); }
                    }
                    catch { }
                });
                t2.IsBackground = true;
                t2.Name = "test-exit";
                try { t2.Start(); } catch { }
            }
        }

        // 退出请求监听：别的进程（命令行 --quit、脚本、自动化测试）置起这个事件，
        // 本实例就走和托盘菜单「退出」完全一样的路径 —— 同一份代码、同一个效果，
        // 不会出现「测试走了一条路、用户走的是另一条路」的偏差。
        private void StartExitWatcher()
        {
            Thread t = new Thread(delegate ()
            {
                IntPtr h = IntPtr.Zero;
                try
                {
                    // 自动复位（manualReset=false）：谁等到谁消费掉这个信号，
                    // 否则一次 --quit 会把事件永久置位，之后每次启动的实例都会立刻自我退出。
                    h = Native.CreateEventW(IntPtr.Zero, false, false, QuitMark.ExitEventName());
                    if (h == IntPtr.Zero) return;
                    Native.ResetEvent(h);   // 防上一次遗留的信号把新实例立刻踢掉
                    while (!disposed)
                    {
                        if (Native.WaitForSingleObject(h, 1000) == 0)
                        {
                            Log.Write("收到外部退出请求（--quit），按手动退出处理");
                            try { uiCtx.Post(delegate { ExitApp("外部请求 --quit", true); }, null); } catch { ExitApp("外部请求 --quit", true); }
                            return;
                        }
                    }
                }
                catch { }
                finally { if (h != IntPtr.Zero) { try { Native.CloseHandle(h); } catch { } } }
            });
            t.IsBackground = true;
            t.Name = "exit-watcher";
            try { t.Start(); } catch { }
        }

        // 手动退出时把两条自愈都停掉：
        //   · 停摆看门狗线程（否则它会把「用户已经退出了」当成「消息循环停摆」再退出一次，
        //     并且可能顺手把单实例锁交出去）；
        //   · 心跳尾巴自检（Tick 里的那段），退出过程中不该再判自己「心跳写不进去」。
        // 注意：退出记录由 Program.Main 的 byAuto 分支负责，这里不碰，避免误消费。
        private void StopSelfHeal()
        {
            watchdogOff = true;
            tailCheckOff = true;
        }

        private ContextMenuStrip BuildMenu()
        {
            ContextMenuStrip m = new ContextMenuStrip();
            m.Items.Add("打开状态窗口", null, delegate { ShowWindow(); });
            m.Items.Add("立即整理内存", null, delegate { TrimNow("手动"); });
            m.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem p = new ToolStripMenuItem("暂停自动整理", null, delegate { TogglePause(); });
            p.Name = "pause";
            m.Items.Add(p);
            m.Items.Add("设置…", null, delegate { ShowSettings(); });
            m.Items.Add("检查有问题的设备…", null, delegate { ShowDevices(); });
            m.Items.Add("看看开机自启项…", null, delegate { ShowStartup(); });
            m.Items.Add("看看后台应用和子进程…", null, delegate { ShowApps(); });
            m.Items.Add("复制当前报告", null, delegate { CopyReport(); });
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("打开历史记录 (CSV)", null, delegate { Open(Config.HistoryPath); });
            m.Items.Add("打开运行日志", null, delegate { Open(Config.LogPath); });
            m.Items.Add("打开配置目录", null, delegate { Open(Config.Dir); });
            m.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem el = new ToolStripMenuItem("以管理员身份重新启动", null, delegate { RelaunchElevated(); });
            if (Trimmer.IsAdmin) el.Enabled = false;
            m.Items.Add(el);
            m.Items.Add(new ToolStripSeparator());
            // 明确写成「退出 SmoothWin…」并加确认框：以前只有一个「退出」，
            // 用户点了之后 5 分钟内又被自愈看门狗拉回来，看起来像「退不掉」。
            m.Items.Add("退出 SmoothWin…", null, delegate { ExitApp("托盘菜单"); });
            return m;
        }

        private static Icon MakeIcon(Color c)
        {
            Bitmap bmp = new Bitmap(16, 16);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                using (SolidBrush b = new SolidBrush(c)) g.FillEllipse(b, 1, 1, 13, 13);
                using (Pen p = new Pen(Color.FromArgb(70, 70, 70))) g.DrawEllipse(p, 1, 1, 13, 13);
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        private void OnPower(object sender, PowerModeChangedEventArgs e)
        {
            if (e.Mode == PowerModes.Resume)
            {
                Log.Write("检测到系统从待机恢复 —— 待机恢复瞬间是显卡驱动崩溃高发点，立即整理一次");
                if (Cfg.AutoTrim) TrimNow("待机恢复");
            }
        }

        // ---- 心跳：证明「进程还活着、消息循环还在转」----
        private DateTime lastHeartbeat = DateTime.MinValue;
        private int tickCount;
        // 上一次「确认心跳文件确实写进去了」的时刻。用来抓「文件系统写不进去」
        // 这种会让进程活着却再也不能留下任何证据的情况。
        private DateTime lastTailOk = DateTime.MinValue;

        private void HeartbeatCheck(bool force)
        {
            try
            {
                int every = Math.Max(10, Cfg.HeartbeatSeconds);
                if (!force && (DateTime.Now - lastHeartbeat) < TimeSpan.FromSeconds(every)) return;
                lastHeartbeat = DateTime.Now;
                Process me = Process.GetCurrentProcess();
                Log.Heartbeat("alive pid=" + me.Id + " 采样次数=" + tickCount
                    + " 工作集=" + Math.Round(me.WorkingSet64 / 1048576.0) + "MB"
                    + " 线程=" + me.Threads.Count
                    + " 自动整理=" + (Cfg.AutoTrim ? "开" : "关"));
            }
            catch { }
        }

        private void Tick()
        {
            try
            {
                if (uiCtx == null) { try { uiCtx = SynchronizationContext.Current; } catch { } }
                tickCount++;
                HeartbeatCheck(false);
                Sample s = Sample.Take();
                last = s;

                if (DateTime.Now - lastHistory >= TimeSpan.FromMinutes(Math.Max(1, Cfg.HistoryMinutes)))
                {
                    lastHistory = DateTime.Now;
                    History.Append(s);
                }

                if (Cfg.WarnOnTdr && (DateTime.Now - lastTdrCheck) >= TimeSpan.FromMinutes(2))
                {
                    lastTdrCheck = DateTime.Now;
                    DateTime t = Events.LastTdrTime();
                    if (t > lastSeenTdr)
                    {
                        lastSeenTdr = t;
                        Log.Write("检测到新的显卡驱动崩溃事件 4101  时间=" + t.ToString("yyyy-MM-dd HH:mm:ss"));
                        Balloon("显卡驱动崩了一次（" + t.ToString("HH:mm") + "）",
                                "屏幕会闪一下或卡住几秒，恢复后一般没事。\n如果一天里反复出现，去显卡官网更新驱动。", ToolTipIcon.Warning);
                    }
                }

                // 顺序有讲究：CheckSystem 先跑，把「哪几个设备的驱动没装好」填进 DevText，
                // CheckStress 生成驱动型建议时才能把「具体是哪几个设备」写进去。
                // 反过来的话，第一轮提醒会退化成「最近装过什么硬件/驱动？」这种没用的套话。
                CheckSystem();
                CheckStress(s);
                CheckLeak(s);

                if (paused)
                {
                    SetIcon(icoOff, "SmoothWin 已暂停（右键恢复）");
                    if (win != null && win.Visible) win.Refresh1();
                    return;
                }

                bool need = false; string why = "";
                if (Cfg.AutoTrim)
                {
                    if (s.CommitPct >= Cfg.CommitThresholdPct) { need = true; why = "提交内存 " + s.CommitPct + "%"; }
                    else if (Cfg.CompressionThresholdMB > 0 && s.CompressionMB >= Cfg.CompressionThresholdMB) { need = true; why = "内存压缩 " + s.CompressionMB + "MB"; }
                }
                if (!need && Cfg.PeriodicTrimMinutes > 0 && (DateTime.Now - lastPeriodic) >= TimeSpan.FromMinutes(Cfg.PeriodicTrimMinutes))
                {
                    need = true; why = "定时维护";
                }

                if (need && (DateTime.Now - lastTrim) >= TimeSpan.FromSeconds(Math.Max(30, Cfg.CooldownSeconds)))
                {
                    TrimNow(why);
                    lastPeriodic = DateTime.Now;
                }

                // 告警线按本机容量算（老版本写死 3072MB，见 TunedPoolNonPagedMB 注释）
                if (s.CommitPct >= 90 || (s.PoolNonPagedMB >= 0 && s.PoolNonPagedMB > Cfg.TunedPoolNonPagedMB()))
                    SetIcon(icoBad, "内存压力高：提交 " + s.CommitPct + "%");
                else if (s.CommitPct >= Cfg.CommitThresholdPct)
                    SetIcon(icoWarn, "内存偏紧：提交 " + s.CommitPct + "%");
                else
                    SetIcon(icoOk, "内存正常：提交 " + s.CommitPct + "%");

                // 尾巴自检：心跳写进去了没有。Log.Heartbeat 内部吞掉一切异常，
                // 若磁盘/权限/杀软把写入挡掉，进程会活着但再也不留证据——这里主动发现它，
                // 让看门狗（IsHung 看心跳文件时间）能接管，而不是永远假装健康。
                if (!tailCheckOff && (DateTime.Now - lastTailOk) >= TimeSpan.FromMinutes(5))
                {
                    lastTailOk = DateTime.Now;
                    try
                    {
                        string hp = Path.Combine(Config.Dir, "heartbeat.log");
                        double tail = Math.Max(300.0, Math.Max(10, Cfg.HeartbeatSeconds) * 4.0);
                        if (!File.Exists(hp) || (DateTime.Now - File.GetLastWriteTime(hp)).TotalSeconds > tail)
                        {
                            Log.Write("心跳文件未能写入（" + hp + "），主动退出让看门狗接管");
                            ExitApp("心跳写不进去");
                            return;
                        }
                    }
                    catch { }
                }

                if (win != null && win.Visible) win.Refresh1();
            }
            catch (Exception ex) { Log.Write("Tick 异常: " + ex.Message); }
        }

        // ---- 换页压力 / 驱动层卡顿提示 ----
        // 硬缺页(Pages Input/sec) = 必须访问硬盘才能满足的缺页，是「内存真的不够」最硬的证据；
        // DPC 时间占比过高通常意味着某个驱动在自旋，是「机器发卡但 CPU 看着不高」的典型原因。
        public static string FormatStress(Sample s)
        {
            return "硬缺页 " + Fmt(s.HardFaultsPerSec) + " 次/秒    DPC " + Fmt(s.DpcPct) + "%    中断 " + Fmt(s.InterruptPct) + "%";
        }

        // 「卡」可能是四件事之一：内存不够、CPU 跑满、磁盘忙不过来、驱动在内核里自旋。
        // 分开量出来，用户才知道该动哪一块，而不是一律去清内存。
        public static string FormatLoad(Sample s)
        {
            return "CPU " + Fmt(s.CpuPct) + "%    磁盘繁忙 " + Fmt(s.DiskBusyPct) + "%"
                 + "（队列 " + Fmt(s.DiskQueue) + "，" + Fmt(s.DiskMBps) + " MB/s）";
        }

        // 进程级 CPU 前几名（数据已在采样时算好，这里只做过滤和排版）
        private string TopCpuUsers(int n)
        {
            try
            {
                Sample s = last;
                if (s == null || s.TopCpu == null) return "";
                StringBuilder sb = new StringBuilder();
                int used = 0;
                for (int i = 0; i < s.TopCpu.Count && used < n; i++)
                {
                    CpuProc c = s.TopCpu[i];
                    if (Trimmer.InList(NotUserClosable, c.Name)) continue;
                    if (c.Name.StartsWith("SmoothWin", StringComparison.OrdinalIgnoreCase)) continue;
                    if (sb.Length > 0) sb.Append("、");
                    sb.Append(c.Name).Append(" ").Append(Math.Round(c.Pct)).Append("%");
                    used++;
                }
                return sb.ToString();
            }
            catch { return ""; }
        }

        // 磁盘读写得最凶的几个「用户侧」进程
        private string TopDiskUsers(int n)
        {
            try
            {
                Sample s = last;
                if (s == null || s.TopDisk == null) return "";
                StringBuilder sb = new StringBuilder();
                int used = 0;
                for (int i = 0; i < s.TopDisk.Count && used < n; i++)
                {
                    CpuProc c = s.TopDisk[i];
                    if (Trimmer.InList(NotUserClosable, c.Name)) continue;
                    if (c.Name.StartsWith("SmoothWin", StringComparison.OrdinalIgnoreCase)) continue;
                    if (sb.Length > 0) sb.Append("、");
                    sb.Append(c.Name).Append(" ").Append(c.Pct.ToString("0.0")).Append(" MB/s");
                    used++;
                }
                return sb.ToString();
            }
            catch { return ""; }
        }

        // ---- 系统层检查（每 10 分钟一次）----
        // 这里检查的都是「程序修不了、但用户一动手就能解决」的事：
        //   ① 有设备的驱动没装好 —— 系统会反复重试加载，表现为「越用越卡」
        //   ② 有改动挂着等重启 —— 不重启就一直用旧状态跑
        // 用户明确要求「能自动处理就自动处理，只有真需要人工介入才提醒」，
        // 这两件事都属于必须人工介入，所以提醒里必须写清具体怎么做。
        private void CheckSystem() { CheckSystem(false); }

        private void CheckSystem(bool force)
        {
            try
            {
                if (!force && (DateTime.Now - lastDevCheck) < TimeSpan.FromMinutes(10)) return;
                lastDevCheck = DateTime.Now;

                List<BadDevice> all = Devices.Scan();
                int bad = 0;
                foreach (BadDevice d in all) if (Devices.IsLikelyCause(d)) bad++;
                BadDeviceCount = bad;
                DevText = Devices.Summary();

                RebootPendingFlag = Reg.RebootPending();
                double days = Sample.Take().UptimeHours / 24.0;

                // 挂了重启 + 已经连续跑了好几天 -> 提醒一次（3 天内不重复）
                if (Cfg.WarnOnReboot && RebootPendingFlag && days >= Math.Max(1, Cfg.RebootNoticeDays)
                    && (DateTime.Now - lastRebootWarn) >= TimeSpan.FromDays(3))
                {
                    lastRebootWarn = DateTime.Now;
                    Log.Write("检测到挂起重启，且已连续运行 " + Math.Round(days, 1) + " 天");
                    Balloon("该重启一次了",
                            "有改动要重启后才生效，而系统已经连续运行 " + Math.Round(days, 1) + " 天。\n" +
                            "重启一次能把这些改动落地。\n点这里看完整说明。", ToolTipIcon.Info);
                }
            }
            catch { }
        }

        // 当前最耗 CPU / 磁盘的是不是「用户自己的程序」。
        // 判据：该进程名不在系统进程名单（NotUserClosable）里，也不是本程序自己。
        // 例：node 编译时 CPU 99% -> node 不在名单里 -> 是用户程序 -> 不打扰。
        private string TopConsumerName(string kind, Sample s)
        {
            try
            {
                List<CpuProc> list = (kind == "磁盘") ? s.TopDisk : s.TopCpu;
                if (list == null) return "";
                for (int i = 0; i < list.Count && i < 5; i++)
                {
                    if (list[i] == null || list[i].Name == null) continue;
                    if (list[i].Name.StartsWith("SmoothWin")) continue;
                    return list[i].Name;
                }
            }
            catch { }
            return "";
        }

        private bool UserProgramIsTopConsumer(string kind, Sample s)
        {
            try
            {
                string top = TopConsumerName(kind, s);
                if (top.Length == 0) return false;
                // 头名是系统进程 -> 不是用户程序，正常走提醒
                if (Trimmer.InList(NotUserClosable, top)) return false;
                // 头名是用户程序，但前 5 名里有系统进程也在猛吃 -> 那是系统问题，仍要提醒
                List<CpuProc> list = (kind == "磁盘") ? s.TopDisk : s.TopCpu;
                double bar = (kind == "磁盘") ? 5.0 : 25.0;   // 磁盘按 MB/s，CPU 按百分比
                if (list != null)
                {
                    for (int i = 0; i < list.Count && i < 5; i++)
                    {
                        if (list[i] == null || list[i].Name == null) continue;
                        if (list[i].Name.StartsWith("SmoothWin")) continue;
                        if (Trimmer.InList(NotUserClosable, list[i].Name) && list[i].Pct >= bar) return false;
                    }
                }
                return true;
            }
            catch { return false; }
        }

        // 判定当前是否处于「持续压力」。单次尖峰不算——打开程序、首次读文件本来就会冲高。
        private void CheckStress(Sample s)
        {
            try
            {
                StressText = FormatStress(s);

                // 判定顺序 = 处理顺序：内存能自动修，优先；CPU/磁盘是「用户态程序的问题」，
                // 提醒了用户就能自己动手；驱动在内核里，只能靠换驱动解决。
                bool memHit = s.HardFaultsPerSec >= 0 && s.HardFaultsPerSec >= Cfg.StressHardFaults;
                bool cpuHit = s.CpuPct >= 0 && s.CpuPct >= Cfg.StressCpuPct;
                bool diskHit = s.DiskBusyPct >= 0 && s.DiskBusyPct >= Cfg.StressDiskPct && s.DiskQueue >= 2;
                bool drvHit = s.DpcPct >= 0 && s.DpcPct >= Cfg.StressDpcPct;
                string kind = memHit ? "内存" : (cpuHit ? "CPU" : (diskHit ? "磁盘" : (drvHit ? "驱动" : "")));

                if (kind.Length == 0)
                {
                    // 压力解除：复位状态机。只有「真的达到过确认次数」或「提醒过/主动跳过过」
                    // 才写日志——单次尖峰（开个程序、读个大文件）也会让 streak=1，
                    // 每来一次就写一行会把日志淹掉，反而看不见真正的事件。
                    if (stressStreak >= Math.Max(2, Cfg.StressConfirmSamples) || stressNotified || stressSkipped || stressFixTries > 0)
                        Log.Write("压力已解除（此前连续 " + stressStreak + " 次超标，自动处理 " + stressFixTries + " 次）");
                    stressStreak = 0; stressFixTries = 0; stressNotified = false; stressSkipped = false; stressKind = "";
                    return;
                }

                if (kind != stressKind) { stressKind = kind; stressStreak = 0; stressFixTries = 0; stressNotified = false; stressSkipped = false; }
                stressStreak++;

                // 还没达到「持续」标准：继续观察，不打扰
                if (stressStreak < Math.Max(2, Cfg.StressConfirmSamples)) return;

                string now = memHit
                    ? "硬缺页 " + Math.Round(s.HardFaultsPerSec) + " 次/秒（阈值 " + Cfg.StressHardFaults + "）"
                    : (cpuHit ? "CPU " + Math.Round(s.CpuPct) + "%（阈值 " + Cfg.StressCpuPct + "%）"
                    : (diskHit ? "磁盘繁忙 " + Math.Round(s.DiskBusyPct) + "%（阈值 " + Cfg.StressDiskPct + "%）"
                    : "DPC 占用 " + Math.Round(s.DpcPct, 1) + "%（阈值 " + Cfg.StressDpcPct + "%）"));

                // ---- 第一优先：能自动修的就自己修掉，不打扰用户 ----
                // 只有「内存型」才自动整理：清工作集对 CPU 跑满、磁盘排队这两种情况
                // 一点用都没有，反而会制造额外的读盘，属于帮倒忙。
                if (memHit && Cfg.AutoFixStress && stressFixTries < Math.Max(0, Cfg.StressFixAttempts))
                {
                    if ((DateTime.Now - lastStressFix) >= TimeSpan.FromSeconds(90))
                    {
                        stressFixTries++;
                        lastStressFix = DateTime.Now;
                        Log.Write("持续换页压力（第 " + stressFixTries + " 次自愈）: " + now + " —— 执行深度整理");
                        TrimResult r = Trimmer.Run(Cfg, "压力自愈", true);   // aggressive：刷新已修改页 + 不受保护名单限制
                        Log.Write("自愈结果: 整理 " + r.Trimmed + " 个进程，可用内存 " + r.BeforeAvailMB + "→" + r.AfterAvailMB
                                  + " MB (" + r.FreedMB.ToString("+#;-#;0") + ")");
                        stressStreak = 0;   // 重置计数，给系统一个观察窗口
                        return;
                    }
                }

                // ---- 第二优先：确实自动处理不了，才提醒，并且必须带「怎么办」 ----
                if (!Cfg.WarnOnStress || stressNotified || stressSkipped) return;

                // ★ 节流：同类提醒最短间隔。压力一旦解除 stressNotified 就会复位，
                //   没有这道闸门时几十秒后又能弹一次（实测日志 22:31:25 / 22:32:10 连弹）。
                if ((DateTime.Now - lastStressWarn) < TimeSpan.FromMinutes(Math.Max(0, Cfg.StressWarnCooldownMinutes)))
                {
                    stressNotified = true;   // 本轮不再弹，但状态照常更新
                    return;
                }

                // ★ 「你正在用它，就别打扰你」：CPU / 磁盘型压力只在人没在用电脑时提醒。
                //   人一直在敲键盘，CPU 高正是因为他自己在编译 / 跑任务 / 看视频，
                //   那正是他要用的程序，提醒他等于让他把自己的活儿关掉。
                //   内存型不设这道门：内存真的见底时不管人在不在用都会卡。
                if (Cfg.StressIdleOnly && !memHit)
                {
                    double idle = Native.IdleMinutes();
                    if (idle >= 0 && idle < Math.Max(1, Cfg.StressIdleMinutes))
                    {
                        // 不置 stressNotified，等人离开后再提醒。
                        // 日志也要节流：这条判断每 5 秒跑一次，不节流会一秒一行刷满日志
                        // （实测 23:22:21~23:22:22 一秒内写了 9 行同样的内容）。
                        stressSkipped = true;   // 本轮已判定「不该打扰」，下一个采样周期不再重新判定
                        if ((DateTime.Now - lastIdleSkipLog) >= TimeSpan.FromMinutes(10))
                        {
                            lastIdleSkipLog = DateTime.Now;
                            Log.Write("检测到" + kind + "压力（" + now + "），但你正在用电脑，暂不打扰（已连续 "
                                      + stressStreak + " 次超标）");
                        }
                        return;
                    }
                }

                // ★ 「占资源的是你自己的程序，就别提醒你」：
                //   用户原话大意：node / firefox 这些我常用、正在用，一直提示我干什么。
                //   如果当前最耗 CPU / 磁盘的正是「用户可关闭的程序」（不在系统进程名单里），
                //   那说明他在编译 / 跑任务 / 开虚拟机 —— 那是他在干活，不是故障。
                //   只有「系统进程自己在空转」（dwm、System、驱动层）才值得提醒。
                if (Cfg.StressIgnoreUserPrograms && !memHit && UserProgramIsTopConsumer(kind, s))
                {
                    stressSkipped = true;   // 同上：用户自己在跑的程序，本轮不再打扰
                    if ((DateTime.Now - lastUserProgSkipLog) >= TimeSpan.FromMinutes(10))
                    {
                        lastUserProgSkipLog = DateTime.Now;
                        Log.Write("检测到" + kind + "压力（" + now + "），占用最多的是你自己的程序（"
                                  + TopConsumerName(kind, s) + "），判定为正常在用，不打扰");
                    }
                    return;
                }

                lastStressWarn = DateTime.Now;
                stressNotified = true;

                string advice = BuildAdvice(kind, s);
                AdviceText = advice;
                Log.Write("需要人工处理: " + now + "\n" + advice);
                // ★ 用户明确要求（原话大意）：firefox、node 这些我还在用，叫我关掉没有意义。
                //   所以气泡文案里不允许出现「关掉某个程序」，只提示「点开看怎么缓解」。
                string shortBody = memHit
                    ? "已自动深度整理 " + stressFixTries + " 次仍未缓解。\n点这里看不关程序也能缓解的办法。"
                    : (cpuHit ? "有个程序一直占着 CPU。\n点这里看是哪一个、怎么处理。"
                    : (diskHit ? "硬盘一直在忙，系统在排队等它。\n点这里看怎么查、怎么缓解。"
                    : "这不是内存问题，程序无权处理驱动。\n点这里看怎么排查。"));
                string title = memHit ? "内存持续吃紧，看一下怎么缓解"
                    : (cpuHit ? "有程序一直占着 CPU，看一下怎么处理"
                    : (diskHit ? "硬盘一直很忙，看一下怎么缓解"
                    : "某个驱动持续占用 CPU，看一下怎么排查"));
                Balloon(title, shortBody, ToolTipIcon.Warning);
            }
            catch { }
        }

        // 找出内存占用最大的几个「用户可关闭的」进程，作为「关掉谁」的具体依据。
        // 系统进程（Memory Compression / dwm 等）必须排除——用户关不掉它们，
        // 列出来只会让人以为「是它的问题」。
        private static readonly string[] NotUserClosable = new string[] {
            "Memory Compression","System","Registry","Idle","Secure System","csrss","wininit","winlogon",
            "services","lsass","smss","dwm","audiodg","fontdrvhost","LsaIso","svchost","conhost",
            "sihost","taskhostw","RuntimeBroker","SearchIndexer","WmiPrvSE","spoolsv","SecurityHealthService",
            "MpDefenderCoreService","MsMpEng","WUDFHost","dllhost","ctfmon","ShellExperienceHost","StartMenuExperienceHost"
        };

        private static string TopMemoryUsers(int n)
        {
            try
            {
                Dictionary<string, long> map = SnapshotByName();
                List<KeyValuePair<string, long>> list = new List<KeyValuePair<string, long>>();
                foreach (KeyValuePair<string, long> kv in map)
                {
                    if (kv.Value < 200) continue;                       // 小于 200MB 的不列
                    if (Trimmer.InList(NotUserClosable, kv.Key)) continue;   // 系统进程不列
                    if (kv.Key.StartsWith("SmoothWin", StringComparison.OrdinalIgnoreCase)) continue;
                    list.Add(kv);
                }
                list.Sort(delegate (KeyValuePair<string, long> a, KeyValuePair<string, long> b) { return b.Value.CompareTo(a.Value); });
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < list.Count && i < n; i++)
                {
                    if (sb.Length > 0) sb.Append("、");
                    sb.Append(list[i].Key).Append(" ").Append(list[i].Value).Append("MB");
                }
                return sb.ToString();
            }
            catch { return ""; }
        }

        // 生成可执行的建议——每条都要是用户能直接照着做的动作
        private string BuildAdvice(string kind, Sample s)
        {
            StringBuilder a = new StringBuilder();
            if (kind == "CPU")
            {
                string topc = TopCpuUsers(3);
                a.Append("CPU 一直跑满（").Append(Fmt(s.CpuPct)).Append("%），这不是内存不够。").AppendLine();
                if (topc.Length > 0) a.Append("占用最多（还在用的）: ").Append(topc).AppendLine();
                a.AppendLine();
                // ★ 前提：这里列出的程序用户很可能正在用（firefox / node / 虚拟机 …），
                //   所以一律不建议「关掉」。给的是「不关也能缓解」的动作。
                a.Append("这些不用关掉，按顺序做：").AppendLine();
                if (topc.Length > 0)
                    a.Append("1. 先确认是谁：任务管理器（Ctrl+Shift+Esc）→「进程」→ 点一下「CPU」列排序").AppendLine();
                else
                    a.Append("1. 打开任务管理器（Ctrl+Shift+Esc）→「进程」→ 点一下「CPU」列排序，看谁在最上面").AppendLine();
                a.Append("2. 浏览器 / 编辑器 / 开发工具这类你还要用的程序不要关：把你在用的那个窗口点到最前，Windows 会自动把前台优先级让给你").AppendLine();
                a.Append("3. 如果是后台在跑任务（编译 / 压缩 / 渲染 / 虚拟机），不用停它：在任务管理器里右键那个进程 →「设置优先级」→ 选「低于正常」，任务照跑，但你在前台操作时系统会先响应你").AppendLine();
                a.Append("4. 如果同一个程序长期 100% 而且越用越慢，多半是它自己卡住了：保存好工作后重启那个程序即可（不用卸载、不用停用）").AppendLine();
                a.Append("5. 杀毒软件全盘扫描（火绒 / Defender）跑完会自己降下来，可以等它，也可以在它界面里点「暂停扫描」").AppendLine();
                a.Append("6. 右键托盘图标 →「打开状态窗口」看完整证据");
                return a.ToString();
            }
            if (kind == "磁盘")
            {
                a.Append("磁盘忙不过来（繁忙 ").Append(Fmt(s.DiskBusyPct)).Append("%  队列 ").Append(Fmt(s.DiskQueue))
                 .Append("  读写 ").Append(Fmt(s.DiskMBps)).Append(" MB/s）。").AppendLine();
                a.Append("系统在排队等硬盘，所以点什么都要顿一下——这也不是内存不够。").AppendLine();
                string topd = TopDiskUsers(3);
                if (topd.Length > 0) a.Append("读写最多（还在用的）: ").Append(topd).AppendLine();
                a.AppendLine();
                a.Append("这些不用关掉，按顺序做：").AppendLine();
                if (topd.Length > 0)
                    a.Append("1. 先确认是谁在读写：任务管理器 →「性能」→「磁盘」，下方就是正在读写的进程").AppendLine();
                else
                    a.Append("1. 打开任务管理器 →「性能」→「磁盘」，下方就是正在读写的进程，按占用排序看谁在最上面").AppendLine();
                a.Append("2. 下面这些都可以「暂停」而不是关掉：Windows 更新（设置 → Windows 更新 → 暂停更新 7 天）、网盘同步（点暂停）、下载工具（暂停任务）、杀毒全盘扫描（点暂停）").AppendLine();
                a.Append("3. 虚拟机 / 编译 / 解压这类正在干活的，让它跑完即可——它占的是顺序读写，等它过这一阵就好").AppendLine();
                a.Append("4. 如果是 Windows 搜索索引（SearchIndexer）一直在扫：设置 → 搜索 → 搜索 Windows →「查找我的文件」改成「经典」，它会少扫很多").AppendLine();
                a.Append("5. 如果一直这样而且硬盘灯常亮，用 CrystalDiskInfo 看一眼硬盘健康度（NVMe 掉速多半是温度或寿命）").AppendLine();
                a.Append("6. 右键托盘图标 →「打开状态窗口」看完整证据");
                return a.ToString();
            }
            if (kind == "内存")
            {
                long availPct = s.TotalMB > 0 ? (100 * s.AvailMB / s.TotalMB) : 0;
                string top = TopMemoryUsers(3);

                a.Append("已自动深度整理 ").Append(stressFixTries).Append(" 次，仍未缓解。").AppendLine();
                if (top.Length > 0) a.Append("占用最多（还在用的）: ").Append(top).AppendLine();
                a.AppendLine();
                // ★ 前提：这里列出的程序用户很可能正在用（firefox / node / 虚拟机 …），
                //   所以一条都不写「关掉它」，只给「不关也能缓解」的动作。
                a.Append("这些不用关掉，按顺序做：").AppendLine();
                a.Append("1. 程序只整理「没在用」的进程：你正在操作的窗口、正在跑任务的进程一律跳过——上面这些还在用的程序不会被清掉，也不需要你去关").AppendLine();
                a.Append("2. 判断内存够不够，看的不是「占用多少」而是「可用多少」：现在可用 ").Append(availPct)
                 .Append("%（约 ").Append(s.AvailMB).Append("MB）。Windows 会把不活跃的部分自动挪到 pagefile，够用就正常用，不用管它").AppendLine();
                if (availPct <= 15)
                    a.Append("3. 可用已经很低了：加内存条是唯一能根治的办法；在加之前，把虚拟内存（pagefile）设大一点能明显减少卡顿").AppendLine();
                else
                    a.Append("3. 可用还有 ").Append(availPct).Append("%，不是「不够用」而是「被占着」——这种情况你正常用即可，卡顿不来自这里").AppendLine();
                a.Append("4. 如果是某个程序越用越大（比如 node / 浏览器跑久了不释放内存）：不用关它，保存好工作后重启它一次就回到初始占用——这类增长换页整理是治不好的，重启才有效").AppendLine();
                a.Append("5. 想看看谁在后台常驻：托盘右键 →「看看开机自启项…」（只读展示，程序不会替你改任何自启项）").AppendLine();
                a.Append("6. 右键托盘图标 →「打开状态窗口」看完整证据");
            }
            else
            {
                // 走到这里说明「内存够、CPU 不满、磁盘不忙」，但 DPC 占用高 ——
                // 这正是驱动在内核里自旋的特征：用户态程序看不见，也管不了。
                a.Append("这不是内存问题（可用内存 ").Append(s.AvailMB).Append("MB 充足），").AppendLine();
                a.Append("是某个驱动在内核里持续自旋，程序无权也不会去动驱动。").AppendLine();
                a.AppendLine();
                // 这一步很关键：把「驱动有问题」落到「这台机器上具体是哪几个设备」
                if (BadDeviceCount > 0 && DevText.Length > 0 && DevText != "尚未检查")
                {
                    a.Append("这台机器上确实有装不上驱动的设备：").AppendLine();
                    a.Append("  ").Append(DevText).AppendLine();
                    a.AppendLine();
                }
                a.Append("建议按顺序做：").AppendLine();
                if (BadDeviceCount > 0 && DevText.Length > 0 && DevText != "尚未检查")
                {
                    a.Append("1. 打开「设备管理器」（Win+X → 设备管理器），带黄色感叹号的就是它们；").AppendLine();
                    a.Append("   右键 →「属性」→「详细信息」→ 选「硬件 ID」，把 VEN_ / DEV_ 记下来").AppendLine();
                    a.Append("2. 拿这两个 ID 去搜，或到电脑/主板厂商支持页面按机型找驱动，装完重启一次").AppendLine();
                    a.Append("3. 外接设备（USB 硬盘/扩展坞/采集卡）拔掉试一次，看 DPC 是否降下来").AppendLine();
                    a.Append("4. 菜单「检查有问题的设备…」里有完整清单，点「重新检查」可复查");
                }
                else
                {
                    a.Append("1. 最近装过什么硬件/驱动？优先更新显卡与网卡驱动").AppendLine();
                    a.Append("2. 外接设备（USB 硬盘/扩展坞/采集卡）拔掉试试").AppendLine();
                    a.Append("3. 用「图吧工具箱」看哪个驱动占的 DPC 时间最高").AppendLine();
                    a.Append("4. 右键托盘图标 →「打开状态窗口」看完整证据");
                }
            }
            return a.ToString();
        }

        // ---- 进程增长追踪（找出真正在漏的程序，而不是笼统地清内存）----
        // 快照按进程名聚合后落盘，这样「托盘实例」和「命令行 --report」用的是同一条基线，
        // 隔几小时跑一次 --report 就能看出到底是谁在涨。
        public static Dictionary<string, long> SnapshotByName()
        {
            Dictionary<string, long> cur = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    string n = p.ProcessName;
                    long mb = p.WorkingSet64 / 1048576L;
                    long old;
                    if (cur.TryGetValue(n, out old)) cur[n] = old + mb; else cur[n] = mb;
                }
                catch { }
                finally { p.Dispose(); }
            }
            return cur;
        }

        private static bool LoadBaseline(out Dictionary<string, long> map, out DateTime when)
        {
            map = null; when = DateTime.MinValue;
            try
            {
                if (!File.Exists(Config.BaselinePath)) return false;
                string[] lines = File.ReadAllLines(Config.BaselinePath);
                if (lines.Length < 2) return false;
                map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
                when = DateTime.Parse(lines[0].Split('\t')[0], CultureInfo.InvariantCulture);
                for (int i = 1; i < lines.Length; i++)
                {
                    string[] p = lines[i].Split('\t');
                    if (p.Length < 2) continue;
                    long mb;
                    if (long.TryParse(p[1], out mb)) map[p[0]] = mb;
                }
                return map.Count > 0;
            }
            catch { return false; }
        }

        private static void SaveBaseline(Dictionary<string, long> map, DateTime when)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(when.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "\t快照");
                foreach (KeyValuePair<string, long> kv in map) sb.AppendLine(kv.Key + "\t" + kv.Value);
                File.WriteAllText(Config.BaselinePath, sb.ToString(), new UTF8Encoding(true));
            }
            catch { }
        }

        // 对比当前与基线，返回可读结论。供托盘气泡与命令行报告共用。
        public static string CompareWithBaseline(long warnMBPerHour, bool saveNew)
        {
            List<string> ignored;
            return CompareWithBaseline(warnMBPerHour, saveNew, null, out ignored);
        }

        // ignored = 正在变大的「已忽略程序」（用户自己点过「别再提醒」的那些）。
        // 报告里要显示它们，但绝不据此弹气泡。
        public static string CompareWithBaseline(long warnMBPerHour, bool saveNew, Config cfg, out List<string> ignored)
        {
            ignored = new List<string>();
            Dictionary<string, long> cur = SnapshotByName();
            Dictionary<string, long> baseMap; DateTime baseTime;
            if (!LoadBaseline(out baseMap, out baseTime))
            {
                // 没有基线时无条件写入：否则命令行报告每次都只会说「已建立基线」而从不落盘。
                SaveBaseline(cur, DateTime.Now);
                return "本次已建立基线（" + DateTime.Now.ToString("MM-dd HH:mm") + "），下次运行即可看到增长对比";
            }

            double hours = (DateTime.Now - baseTime).TotalHours;
            // 对比窗口太短时，任何一点波动外推成「每小时」都会变成天文数字（曾出现 90188MB/时），
            // 所以短窗口只报绝对增长量，不做速率外推、也不据此告警。
            bool canRate = hours >= 0.5;
            if (hours < 0.25) return "基线刚建立 " + Math.Round(hours * 60) + " 分钟，积累 15 分钟后才有对比意义";

            List<KeyValuePair<string, long>> growers = new List<KeyValuePair<string, long>>();
            int sysGrow = 0;
            foreach (KeyValuePair<string, long> kv in cur)
            {
                long old;
                if (!baseMap.TryGetValue(kv.Key, out old)) continue;   // 新起的进程不算增长
                long d = kv.Value - old;
                if (d < 50) continue;
                // 系统进程（内存压缩/内核/服务宿主等）用户既看不到也关不掉，报出来只会让人困惑
                if (Trimmer.InList(NotUserClosable, kv.Key)) { sysGrow++; continue; }
                if (canRate && (d / hours) >= warnMBPerHour)
                {
                    // 用户已经说过「这个我知道」的程序，只记录不告警。
                    if (cfg != null && cfg.IsLeakIgnored(kv.Key)) ignored.Add(kv.Key);
                    else growers.Add(new KeyValuePair<string, long>(kv.Key, d));
                }
            }
            growers.Sort(delegate (KeyValuePair<string, long> a, KeyValuePair<string, long> b) { return b.Value.CompareTo(a.Value); });

            StringBuilder sb = new StringBuilder();
            sb.Append("对比 ").Append(Math.Round(hours, 1)).Append(" 小时   ");
            if (growers.Count == 0)
            {
                if (ignored.Count > 0)
                {
                    sb.Append("在涨的只有你标记过「不用提醒」的：");
                    for (int i = 0; i < ignored.Count && i < 3; i++) { if (i > 0) sb.Append("、"); sb.Append(ignored[i]); }
                }
                else sb.Append(sysGrow > 0 ? "用户程序里没有在变大的（只有系统进程在涨，属正常缓存）" : "无异常增长");
            }
            else
            {
                sb.Append("增长最快: ");
                for (int i = 0; i < growers.Count && i < 3; i++)
                {
                    if (i > 0) sb.Append("、");
                    sb.Append(growers[i].Key).Append(" +").Append(growers[i].Value).Append("MB");
                    if (canRate) sb.Append("(").Append(Math.Round(growers[i].Value / hours)).Append("MB/时)");
                }
                if (sysGrow > 0) sb.Append("（另有 ").Append(sysGrow).Append(" 个系统进程在涨，属正常）");
                if (ignored.Count > 0) sb.Append("；另有 ").Append(ignored.Count).Append(" 个已忽略");
            }
            // 基线是「长期锚点」：调用方每次检查都传 saveNew=true，若每次都刷新，
            // 对比窗口永远只有几分钟，根本看不出「越用越大」的泄漏。
            if (saveNew && hours >= 12) SaveBaseline(cur, DateTime.Now);
            return sb.ToString();
        }

        private void CheckLeak(Sample s)
        {
            try
            {
                if (Cfg.LeakSampleMinutes <= 0) { LeakText = "已关闭"; return; }
                if ((DateTime.Now - lastLeakScan) < TimeSpan.FromMinutes(Cfg.LeakSampleMinutes)) return;
                lastLeakScan = DateTime.Now;

                List<string> ignoredNow;
                LeakText = CompareWithBaseline(Cfg.LeakWarnMBPerHour, true, Cfg, out ignoredNow);

                // 找出「增长最快」的那个程序名。它同时充当连续确认的比较键 ——
                // 不能用 LeakText 整串当键：里面带着「对比 3.4 小时」这种每次都变的部分，
                // 结果就是每轮都算「换了对象」，计数永远回到 1，再也不会提醒。
                string who = "";
                int c1 = LeakText.IndexOf("增长最快: ");
                if (c1 >= 0)
                {
                    string tail = LeakText.Substring(c1 + 5);
                    int cut = tail.IndexOf('+');
                    if (cut > 0) who = tail.Substring(0, cut).Trim();
                }

                if (who.Length == 0) { leakStreak = 0; leakStreakKey = ""; return; }
                if (who == leakStreakKey) leakStreak++;
                else { leakStreakKey = who; leakStreak = 1; }

                // ★ 连续确认：启动那一刻、程序刚跑起来时本来就在长，第一次不提醒。
                //   LeakSampleMinutes 默认 5 分钟，LeakWarnConfirm 默认 3，
                //   所以最早的提醒出现在运行 15 分钟之后，而不是每次开机就弹。
                if (!Cfg.WarnOnLeak || leakStreak < Math.Max(1, Cfg.LeakWarnConfirm)) return;

                // ★ 用户说过「这个我知道」的程序（node 之类开发工具）：只写日志，永远不弹。
                if (Cfg.IsLeakIgnored(who)) return;

                // 同一现象 6 小时内不重复打扰
                if (who == lastLeakWarnKey && (DateTime.Now - lastLeakWarnTime) < TimeSpan.FromHours(6)) return;
                lastLeakWarnKey = who; lastLeakWarnTime = DateTime.Now;

                // ★ 同一个程序提醒够多次就自动静音：提醒它的目的只是让用户知道
                //   「有东西在长大」，不是要他天天看同一句话。
                int seen = 0;
                leakSeen.TryGetValue(who, out seen);
                seen++;
                leakSeen[who] = seen;
                int muteAfter = Cfg.LeakMuteAfter;
                bool muted = muteAfter > 0 && seen >= muteAfter;
                if (muted) { Cfg.AddLeakIgnore(who); try { Cfg.Save(); } catch { } }

                Log.Write("疑似内存增长（连续 " + leakStreak + " 次确认，第 " + seen + " 次提醒"
                        + (muted ? "，已自动静音" : "") + "）: " + LeakText);
                // ★ 只报告「谁在变大」，不提「关掉」——这类程序用户通常正在用。
                //   点一下气泡就能把它加进忽略名单（node 这类开发工具，用户明确说过提醒没用）。
                pendingLeakIgnore = who;
                pendingLeakIgnoreTime = DateTime.Now;
                Balloon("发现越用越大的程序", LeakBalloonText(who, muted), ToolTipIcon.Info);
            }
            catch { }
        }

        // 增长提醒气泡的正文（单独抽出来，自检里能直接打印核对）。
        // 用户原话（m02159）：「像 firefox node 这些都是常用的，我还要用呢 提醒有啥用，
        // 我还要用没办法啊」—— 所以这里一句「要你去关它」的话都不能有，
        // 只留两件用户真能做的事：看数据、别再提醒。
        internal static string LeakBalloonText(string who, bool muted)
        {
            return who + " 一直在变大。\n"
                 + "浏览器、编辑器、开发工具这类程序越用越大是正常的 —— 你不用关它，也不用做任何事。\n"
                 + (muted ? "这是最后一次提醒，以后不再打扰。\n" : "")
                 + "点这个气泡：看详细数据，或者让 SmoothWin 以后别再提醒它。";
        }

        private static string Fmt(double v) { return v < 0 ? "N/A" : Math.Round(v, 1).ToString(CultureInfo.InvariantCulture); }


        private void SetIcon(Icon i, string tip)
        {
            try
            {
                if (ni.Icon != i) ni.Icon = i;
                if (tip.Length > 62) tip = tip.Substring(0, 62);
                ni.Text = tip;
            }
            catch { }
        }

        public void TrimNow(string trigger)
        {
            try
            {
                TrimResult r = Trimmer.Run(Cfg, trigger, false);
                lastTrim = DateTime.Now;
                // 把「主动跳过了多少」也写进去：用户能一眼看出正在用的程序确实没被碰。
                lastTrimText = string.Format("{0:HH:mm:ss} [{1}] 整理 {2} 个进程，失败 {3}，跳过 {4} 个（在用/在跑/刚整理过），可用内存 {5}→{6} MB ({7:+#;-#;0})",
                    DateTime.Now, trigger, r.Trimmed, r.Failed, r.SkippedUsing + r.SkippedBusy + r.SkippedRecent,
                    r.BeforeAvailMB, r.AfterAvailMB, r.FreedMB);
                Log.Write(lastTrimText);
                // 用户要求「毫无感知」：自动整理只写日志，不弹气泡。
                // 但手动点击「立即整理内存」仍然给出反馈，否则会以为没生效。
                if (trigger == "手动")
                    Balloon("已整理内存", "释放可用内存 " + r.FreedMB + " MB", ToolTipIcon.Info);
                else if (!Cfg.SilentAutoTrim)
                    Balloon("已自动整理内存", "触发原因: " + trigger + "\n释放可用内存 " + r.FreedMB + " MB", ToolTipIcon.Info);
            }
            catch (Exception ex) { Log.Write("整理失败: " + ex.Message); }
        }

        public void TogglePause()
        {
            paused = !paused;
            Log.Write(paused ? "已暂停自动整理" : "已恢复自动整理");
            ContextMenuStrip m = ni.ContextMenuStrip;
            foreach (ToolStripItem it in m.Items)
                if (it.Name == "pause") it.Text = paused ? "恢复自动整理" : "暂停自动整理";
            if (!paused) Tick();
        }

        public void ShowWindow()
        {
            if (win == null || win.IsDisposed)
            {
                win = new StatusForm(this);
            }
            win.Show();
            win.WindowState = FormWindowState.Normal;
            win.Activate();
            win.Refresh1();
        }

        public void ShowSettings()
        {
            using (SettingsForm f = new SettingsForm(this)) { f.ShowDialog(); }
        }

        // 把当前报告整段复制到剪贴板：用户要把情况发给别人（或自己存档）时不用截图
        public void CopyReport()
        {
            try
            {
                string txt = BuildReport();
                if (string.IsNullOrEmpty(txt))
                {
                    Balloon("没有可复制的内容", "报告还是空的，等几秒再试。", ToolTipIcon.Info);
                    return;
                }
                Clipboard.SetText(txt);
                Balloon("已复制到剪贴板", "报告全文（" + txt.Length + " 字）已复制，直接粘贴即可。", ToolTipIcon.Info);
            }
            catch (Exception ex) { Balloon("复制失败", ex.Message, ToolTipIcon.Warning); }
        }

        // 「看看开机自启项」：把「降低常驻负载」这件用户自己该做的事变成看得见、动得了的数据。
        // ★ 这里永远只响应用户在窗口里的点击，程序自己绝不自动禁用任何一项
        //   （之前自动关自启把用户的远控软件弄没了，那是绝对不能重演的）。
        // 报告里只放一行摘要，详细列表在「看看开机自启项…」窗口里
        private string StartupCountText()
        {
            try
            {
                // 状态窗口每秒刷新一次，这里必须缓存，否则每秒枚举一遍全部进程
                if (startupText != null && (DateTime.Now - lastStartupScan) < TimeSpan.FromMinutes(2))
                    return startupText;
                lastStartupScan = DateTime.Now;
                List<StartItem> list = Startup.Scan();
                int running = 0;
                long total = 0;
                foreach (StartItem it in list) if (it.RunningMB > 0) { running++; total += it.RunningMB; }
                startupText = list.Count + " 项，正在运行 " + running + " 项，合计 " + total + " MB"
                              + (total >= 2048 ? "  ← 想减负载可以先从这里下手" : "");
                return startupText;
            }
            catch { return "读取失败"; }
        }

        public void ShowStartup()
        {
            try
            {
                using (StartupForm f = new StartupForm(this)) { f.ShowDialog(); }
                // 窗口里可能刚禁用/启用过几项，摘要缓存必须作废，否则状态窗口还显示旧数字。
                startupText = null;
                lastStartupScan = DateTime.MinValue;
            }
            catch (Exception ex) { Balloon("读取自启项失败", ex.Message, ToolTipIcon.Warning); }
        }

        // 「看看后台应用」：和自启项刻意分成两个窗口。
        //   自启项 = 注册表里的静态清单（开机时谁自己起来）；
        //   后台应用 = 此刻内存里的活进程树（谁在跑、跑了多久、谁生了谁、能不能关）。
        // 混在一个表格里两边都看不清楚，用户明确要求拆开。
        public void ShowApps()
        {
            try
            {
                using (AppForm f = new AppForm(this)) { f.ShowDialog(); }
            }
            catch (Exception ex) { Balloon("读取后台应用失败", ex.Message, ToolTipIcon.Warning); }
        }

        // 「检查有问题的设备」：把设备管理器里那些黄色感叹号列出来，
        // 并给出「去哪装什么驱动」——这是程序唯一修不了、但能帮用户定位的事。
        public void ShowDevices()
        {
            try
            {
                List<BadDevice> all = Devices.Scan();
                List<BadDevice> hit = new List<BadDevice>();
                foreach (BadDevice d in all) if (Devices.IsLikelyCause(d)) hit.Add(d);

                StringBuilder b = new StringBuilder();
                b.AppendLine("SmoothWin 设备检查   " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                b.AppendLine();
                if (hit.Count == 0)
                {
                    b.AppendLine("没有发现会影响性能的设备问题。");
                    b.AppendLine();
                    b.AppendLine("（未接入的 U 盘、没连上的蓝牙耳机这类不算问题，已自动忽略）");
                }
                else
                {
                    b.AppendLine(Devices.Advice());
                    b.AppendLine();
                    b.AppendLine("--- 全部异常设备 ---");
                    foreach (BadDevice d in all)
                    {
                        b.AppendLine((Devices.IsLikelyCause(d) ? "[影响] " : "[忽略] ") + d.Display
                                     + "  ——  " + d.MeaningShort);
                        b.AppendLine("        " + d.Instance);
                    }
                }
                b.AppendLine();
                b.AppendLine("--- 挂起重启 ---");
                b.AppendLine(Reg.RebootPending()
                    ? "有改动要重启后才生效。重启一次能把这些改动落地。"
                    : "没有挂起的重启项。");
                b.AppendLine("已连续运行 " + (Sample.Take().UptimeHours / 24).ToString("0.0") + " 天");

                using (DevForm f = new DevForm(b.ToString())) { f.ShowDialog(); }
            }
            catch (Exception ex) { Balloon("设备检查失败", ex.Message, ToolTipIcon.Warning); }
        }

        public void Reconfigure()
        {
            // 命令行模式（TrayApp(true)）没有定时器，这里必须判空，
            // 否则 --settingshot 自检在保存那一步会抛 NullReferenceException。
            if (timer != null) timer.Interval = Math.Max(1, Cfg.SampleSeconds) * 1000;
            // 设置窗口里可能刚把某一项切回「自动」，这里立刻按当前物理内存重算一次，
            // 不用等下次启动。
            try { Cfg.ApplyAutoTune(Sample.Take().TotalMB); } catch { }
        }

        public void OpenLog() { Open(Config.LogPath); }
        private void Open(string path)
        {
            try { Process.Start("notepad.exe", "\"" + path + "\""); }
            catch { try { Process.Start("explorer.exe", "/select,\"" + path + "\""); } catch { } }
        }

        internal void RelaunchElevated()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
                // 重启前先把单实例锁交出去：互斥体是「进程还持有」的状态，
                // 不释放的话新实例会判定「已有实例在运行」而静默退出（实测踩过）。
                Program.ReleaseSingleInstance();
                ExitApp("切换管理员身份");
            }
            catch { Balloon("提权取消", "未能以管理员身份重新启动。", ToolTipIcon.Warning); }
        }

        // 气泡被点击：泄漏气泡附带一个「以后别再提醒它」的选择，其余气泡照旧只开窗口。
        private void OnBalloonClicked()
        {
            try
            {
                string who = pendingLeakIgnore;
                pendingLeakIgnore = null;
                bool fresh = who != null && who.Length > 0
                          && (DateTime.Now - pendingLeakIgnoreTime) < TimeSpan.FromSeconds(90);
                if (fresh)
                {
                    DialogResult r = MessageBox.Show(
                        "以后不再提醒「" + who + "」的内存增长吗？\n\n"
                        + "「是」= 加入忽略名单：它再变大也不再弹气泡（详细报告里仍然会记）。\n"
                        + "「否」= 继续提醒。\n\n"
                        + "想改回来：设置… →「增长提醒忽略名单」。",
                        "内存增长提醒", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                        MessageBoxDefaultButton.Button1);
                    if (r == DialogResult.Yes)
                    {
                        Cfg.AddLeakIgnore(who);
                        try { Cfg.Save(); } catch { }
                        Log.Write("用户把「" + who + "」加入增长提醒忽略名单");
                    }
                }
            }
            catch { }
            ShowWindow();
        }

        public void Balloon(string title, string text, ToolTipIcon icon)
        {
            try
            {
                // 从后台线程（状态窗口刷新）调用时切回 UI 线程，否则气泡可能不显示
                SynchronizationContext cur = SynchronizationContext.Current;
                if (uiCtx != null && cur != uiCtx)
                {
                    uiCtx.Post(delegate { Balloon(title, text, icon); }, null);
                    return;
                }
                ni.BalloonTipTitle = title; ni.BalloonTipText = text; ni.BalloonTipIcon = icon; ni.ShowBalloonTip(6000);
            }
            catch { }
        }

        // ==================== 界面数据（跑在后台线程里） ====================
        // 状态窗口每秒调一次。采样、事件日志查询、拼字符串全在这里做，
        // UI 线程只负责把结果贴到卡片上 —— 这是「点通知进来不再未响应」的关键。
        // 以前 BuildReport 直接在 UI 线程上跑，里面 4 次事件日志查询各约 300 毫秒，
        // 窗口每秒钟被堵住 1.5 秒，必然「未响应」。
        public UiData BuildUiData()
        {
            UiData d = new UiData();
            try
            {
                Sample s = last;
                if (s == null || (DateTime.Now - s.Time).TotalMilliseconds > 1000)
                {
                    s = Sample.Take();
                    if (s != null) last = s;
                }
                if (s == null) s = new Sample();

                d.Ok = true;
                d.Time = DateTime.Now.ToString("HH:mm:ss");
                d.Uptime = s.UptimeHours.ToString("0.0", CultureInfo.InvariantCulture);
                d.Perm = Trimmer.IsAdmin ? "管理员" : "普通用户";
                d.RunState = paused ? "已暂停自动整理" : "自动整理运行中";

                d.AvailMB = s.AvailMB; d.TotalMB = s.TotalMB;
                d.CommitMB = s.CommitMB; d.CommitLimitMB = s.CommitLimitMB; d.CommitPct = s.CommitPct;
                d.CompressionMB = s.CompressionMB; d.StandbyMB = s.StandbyMB; d.ModifiedMB = s.ModifiedMB;
                d.PoolNonPagedMB = s.PoolNonPagedMB; d.PoolPagedMB = s.PoolPagedMB;
                d.Procs = s.Procs; d.Threads = s.Threads; d.Handles = s.Handles;
                d.HardFaultsPerSec = s.HardFaultsPerSec; d.DpcPct = s.DpcPct; d.InterruptPct = s.InterruptPct;
                d.CpuPct = s.CpuPct; d.DiskBusyPct = s.DiskBusyPct; d.DiskQueue = s.DiskQueue; d.DiskMBps = s.DiskMBps;
                d.CommitThreshold = Cfg.CommitThresholdPct;
                d.HardFaultThreshold = Cfg.StressHardFaults;
                d.PerfError = s.PerfError == null ? "" : s.PerfError;

                // ---- 系统设置（都是读注册表，微秒级）----
                d.FastStartupOff = Reg.FastStartupDisabled();
                object td = Reg.TdrDelay();
                int tdn = 0;
                if (td != null) { try { tdn = Convert.ToInt32(td); } catch { tdn = 0; } }
                d.TdrOk = tdn >= 8;
                d.TdrText = (td == null)
                          ? "默认 2 秒 —— 建议改成 10 秒"
                          : tdn + " 秒" + (d.TdrOk ? " ✓" : " —— 建议改成 10 秒");
                d.AutoStart = Reg.IsAutoStartEnabled();
                d.RebootPending = RebootPendingFlag;

                // ---- 状态机快照（Tick 里维护）----
                d.StressKind = stressKind == null ? "" : stressKind;
                d.StressStreak = stressStreak;
                d.StressFixTries = stressFixTries;
                d.Advice = AdviceText == null ? "" : AdviceText;
                d.StressText = StressText == null ? "" : StressText;
                d.LoadText = FormatLoad(s);
                d.LastTrim = lastTrimText == null ? "" : lastTrimText;
                d.NeedHelp = d.StressKind.Length > 0;

                // ---- 事件计数（Events.Count 自带 10 分钟缓存，命中时几乎不耗时）----
                d.Tdr4101 = (int)Events.Count("Display", 4101, 24);
                long w17 = Events.Count("Microsoft-Windows-WHEA-Logger", 17, 24);
                long w18 = Events.Count("Microsoft-Windows-WHEA-Logger", 18, 24);
                long w19 = Events.Count("Microsoft-Windows-WHEA-Logger", 19, 24);
                d.Whea = (w17 < 0 || w18 < 0 || w19 < 0) ? -1 : (int)(w17 + w18 + w19);

                // ---- 设备（CheckSystem 自带 10 分钟节流，这里只读它的结果）----
                if (DevText == "尚未检查") CheckSystem(true);
                d.DevText = DevText == null ? "" : DevText;
                d.BadDevices = BadDeviceCount;
                d.DeviceAdvice = BadDeviceCount > 0 ? Devices.Brief() : "";   // 卡片用短版，全文留给「详细报告」

                d.StartupText = StartupCountText();

                // ---- 增长追踪：CheckLeak 已按 LeakSampleMinutes 采过，直接用 ----
                string lk = LeakText == null ? "" : LeakText;
                if (lk.Length == 0 || lk.StartsWith("尚未"))
                    lk = CompareWithBaseline(Cfg.LeakWarnMBPerHour, false);
                d.LeakText = lk;

                // 纯文本报告只留给「详细报告」按钮，顺手生成一份（事件计数已缓存，约 40 毫秒）
                d.FullText = BuildReport();
            }
            catch (Exception ex)
            {
                try { Log.Write("界面数据生成失败: " + ex.Message); } catch { }
            }
            return d;
        }

        public string BuildReport()
        {
            // 有 1 秒内的新鲜样本就直接用，否则现采一次。
            // 整轮采样只要 30 毫秒左右（见 Sample.TakePerProcess 的注释），
            // 不需要为了「别卡住 UI」而去用后台线程 + 缓存 —— 那样只会显示过期数字。
            // 速率型计数器自带窗口守卫：间隔不够时沿用上一次的值，
            // 所以每秒刷新一次状态窗口拿到的仍然是有意义的读数。
            Sample s = last;
            if (s == null || (DateTime.Now - s.Time).TotalMilliseconds > 1000)
            {
                s = Sample.Take();
                if (s != null) last = s;
            }
            if (s == null) s = new Sample();
            StringBuilder b = new StringBuilder();
            b.AppendLine("SmoothWin 常驻监控   " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            b.AppendLine("运行权限 : " + (Trimmer.IsAdmin ? "管理员（可整理全部进程）" : "普通用户（部分系统进程会被跳过，建议以管理员身份运行）"));
            b.AppendLine("运行状态 : " + (paused ? "已暂停自动整理" : "自动整理运行中"));
            b.AppendLine("已运行   : " + s.UptimeHours + " 小时");
            b.AppendLine();

            // 需要人工处理的事情顶到最前面：用户点通知进来，第一眼就该看到「该干什么」
            if (stressKind.Length > 0)
            {
                b.AppendLine("################################################");
                b.AppendLine("##  需要你处理一下（自动处理没能解决）        ##");
                b.AppendLine("################################################");
                b.AppendLine(AdviceText);
                b.AppendLine();
            }
            b.AppendLine("--- 内存 ---");
            b.AppendLine("物理内存 : 可用 " + s.AvailMB + " MB / 共 " + s.TotalMB + " MB");
            b.AppendLine("提交内存 : " + s.CommitMB + " MB / " + s.CommitLimitMB + " MB  (" + s.CommitPct + "%)  阈值 " + Cfg.CommitThresholdPct + "%");
            b.AppendLine("非分页池 : " + Show(s.PoolNonPagedMB) + " MB    分页池 : " + Show(s.PoolPagedMB) + " MB");
            if (s.PoolNonPagedMB >= 0)
                b.AppendLine("          告警线 " + Cfg.TunedPoolNonPagedMB() + " MB（按本机物理内存 " + s.TotalMB + " MB 推算）");
            b.AppendLine("待机缓存 : " + Show(s.StandbyMB) + " MB    已修改 : " + Show(s.ModifiedMB) + " MB");
            b.AppendLine("内存压缩 : " + s.CompressionMB + " MB   阈值 " + Cfg.CompressionThresholdMB + " MB");
            b.AppendLine("进程/线程/句柄 : " + s.Procs + " / " + s.Threads + " / " + s.Handles);
            if (Cfg.AutoTune && !Cfg.UserSetCommit && !Cfg.UserSetComp && !Cfg.UserSetMinTrim)
                b.AppendLine("阈值来源 : 提交/压缩/整理下限 均已按本机物理内存(" + s.TotalMB + "MB)自动设定，可在「设置」里改");
            else if (Cfg.AutoTune)
                b.AppendLine("阈值来源 : 部分为你手动设定，其余按物理内存(" + s.TotalMB + "MB)自动设定");
            else
                b.AppendLine("阈值来源 : 完全手动设定（自动调优已关闭）");
            if (s.PerfError.Length > 0) b.AppendLine("注意     : " + s.PerfError + "，池数据不可用（可运行 lodctr /r 修复）");
            b.AppendLine();
            b.AppendLine("--- 系统设置 ---");
            b.AppendLine("快速启动 : " + (Reg.FastStartupDisabled() ? "已关闭（好：关机才会真正清理内核状态）" : "开启中（建议关闭：这正是「只有真重启才恢复」的原因）"));
            object td = Reg.TdrDelay();
            b.AppendLine("TdrDelay : " + (td == null ? "默认 2 秒（建议设为 10）" : td + " 秒"));
            b.AppendLine("开机自启 : " + (Reg.IsAutoStartEnabled() ? "已启用" : "未启用"));
            // 命令行 --report 不跑 Tick，首次进这里时设备项还是「尚未检查」，即时扫一次
            if (DevText == "尚未检查") CheckSystem(true);
            b.AppendLine("设备驱动 : " + DevText);
            b.AppendLine("自启项   : " + StartupCountText());
            if (RebootPendingFlag)
                b.AppendLine("挂起重启 : 有改动要重启后才生效（已经连续运行 " + (s.UptimeHours / 24).ToString("0.0") + " 天，建议尽快重启一次）");
            b.AppendLine();
            b.AppendLine("--- 事件（近 24 小时）---");
            b.AppendLine("显卡驱动崩溃 4101 : " + Show(Events.Count("Display", 4101, 24)) + " 次");
            long w17 = Events.Count("Microsoft-Windows-WHEA-Logger", 17, 24);
            long w18 = Events.Count("Microsoft-Windows-WHEA-Logger", 18, 24);
            long w19 = Events.Count("Microsoft-Windows-WHEA-Logger", 19, 24);
            b.AppendLine("WHEA 硬件错误     : " + ((w17 < 0 || w18 < 0 || w19 < 0) ? "N/A" : (w17 + w18 + w19) + " 次"));
            b.AppendLine();
            b.AppendLine("--- 实时压力（判断「卡」到底卡在哪）---");
            b.AppendLine("换页压力 : " + (StressText == "未采样" ? FormatStress(s) : StressText));
            b.AppendLine("系统负载 : " + FormatLoad(s));
            string diskTop = TopDiskUsers(3);
            if (diskTop.Length > 0) b.AppendLine("磁盘读写 : " + diskTop);
            b.AppendLine("增长追踪 : " + (LeakText.StartsWith("尚未") ? CompareWithBaseline(Cfg.LeakWarnMBPerHour, false) : LeakText));
            b.AppendLine("压力状态 : " + (stressKind.Length == 0 ? "正常" : stressKind + "压力持续中（连续 " + stressStreak + " 次超标，已自愈 " + stressFixTries + " 次）"));
            b.AppendLine();
            b.AppendLine("--- 诊断与建议 ---");
            if (BadDeviceCount > 0)
            {
                string da = Devices.Advice();
                if (da.Length > 0) { b.AppendLine(da); b.AppendLine(); }
                // 有设备问题时别再显示「暂无需处理」，那两句放一起会自相矛盾
                if (AdviceText.StartsWith("暂无需处理"))
                {
                    b.AppendLine("做完上面这几步、重启一次，再回来看这一行。");
                    b.AppendLine("如果装完驱动还是卡，看上面的「增长追踪」：程序只整理「没在用」的进程，");
                    b.AppendLine("你正在用的 firefox / node / 虚拟机不会被清掉，也不需要你去关。");
                    b.AppendLine();
                    b.AppendLine("--- 最近整理 ---");
                    b.AppendLine(lastTrimText);
                    b.AppendLine();
                    b.AppendLine("说明: 本程序只修剪「没在用」的后台进程工作集，不碰内核池、不改系统设置。");
                    b.AppendLine("      正在操作的窗口、正在跑任务的进程会被主动跳过（见「最近整理」里的跳过数）。");
                    b.AppendLine("      历史曲线记录在 history.csv，卡顿时可对照看是哪一项在涨。");
                    return b.ToString();
                }
            }
            b.AppendLine(AdviceText);
            b.AppendLine();
            b.AppendLine("--- 最近整理 ---");
            b.AppendLine(lastTrimText);
            b.AppendLine();
            b.AppendLine("说明: 本程序只修剪「没在用」的后台进程工作集，不碰内核池、不改系统设置。");
            b.AppendLine("      正在操作的窗口、正在跑任务的进程会被主动跳过（见「最近整理」里的跳过数）。");
            b.AppendLine("      历史曲线记录在 history.csv，卡顿时可对照看是哪一项在涨。");
            return b.ToString();
        }

        private static string Show(long v) { return v < 0 ? "N/A" : v.ToString(); }

        public void ExitApp() { ExitApp("内部"); }

        // manual = 用户明确点的「退出」。只有这一种才会写「退出记录」并把自愈看门狗停掉；
        // 内部自愈（假死、心跳写不进去）走的还是普通退出，保证该自愈的仍然自愈。
        public void ExitApp(string reason)
        {
            ExitApp(reason, false);
        }

        public void ExitApp(string reason, bool manual)
        {
            if (disposed) return;
            if (manual && !ConfirmExit()) return;   // 用户点了「取消」就什么都不做
            disposed = true;

            string detail = "";
            if (manual)
            {
                StopSelfHeal();
                // 只写记录，不动计划任务。
                // 计划任务一旦被停用，就连「开机自启」也一起没了（schtasks /change /disable
                // 停的是整个任务、不是单条触发器），设置窗口里勾着的「开机自动启动」就变成了假象。
                // 留着任务不动，靠记录拦住它：5 分钟触发点拉起的实例带 --auto，
                // 启动第一件事就是看到这条记录然后静默退出（不建托盘图标，用户看不见）。
                detail = QuitMark.Set() ? "已记录（自启拉起的实例会静默退出）" : "记录失败";
            }

            Log.Write("SmoothWinTray 退出  原因=" + reason + (manual ? "（用户手动）" : "") + (detail.Length > 0 ? "  看门狗=" + detail : ""));
            Log.Heartbeat((manual ? "手动退出 pid=" : "正常退出 pid=") + Process.GetCurrentProcess().Id + "  原因=" + reason);
            try { timer.Stop(); } catch { }
            try { SystemEvents.PowerModeChanged -= OnPower; } catch { }
            try { ni.Visible = false; ni.Dispose(); } catch { }
            ExitThread();
        }

        // 手动退出的确认框。这是唯一一个非「自动处理」的交互，但它决定的是
        // 「程序到底还跑不跑」，属于必须由用户拍板的事。
        private bool ConfirmExit()
        {
            if (Config.TestMode)
            {
                Log.Write("测试模式（--testdir）：退出确认框自动回答「是」");
                return true;
            }
            try
            {
                string t = "确定要退出 SmoothWin 吗？";
                string m = "退出后不再自动整理内存，也不会再自动启动（下次开机/登录仍会启动）。\n\n"
                         + "想临时让它别插手，用「暂停自动整理」更合适 —— 那样它还在看着，只是不动手。";
                return MessageBox.Show(m, t, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2)
                       == DialogResult.Yes;
            }
            catch { return true; }
        }
    }

    // ==================== 入口 ====================
    internal static class Program
    {
        // 命令行模式（供计划任务/脚本调用，不弹窗口、不驻留）
        //   SmoothWinTray.exe --trim [--out 文件]     立即整理一次并写出结果
        //   SmoothWinTray.exe --report [--out 文件]   写出状态报告
        //   SmoothWinTray.exe --selftest [--out 文件] 自检（注册表/性能计数器/事件日志/API 可用性）
        private static int RunCli(string[] args)
        {
            string mode = args[0].TrimStart('-').ToLowerInvariant();
            string outFile = null;
            for (int i = 1; i < args.Length - 1; i++)
                if (args[i] == "--out") outFile = args[i + 1];
            if (outFile == null)
                outFile = Path.Combine(Config.Dir, "cli-" + mode + ".txt");

            StringBuilder b = new StringBuilder();
            try { RunCliCore(mode, b); }
            catch (Exception ex) { b.AppendLine(); b.AppendLine("[异常] " + ex.ToString()); }

            try
            {
                File.WriteAllText(outFile, b.ToString(), new UTF8Encoding(true));
                Log.Write("命令行 " + mode + " 完成，输出 -> " + outFile);
            }
            catch (Exception ex) { Log.Write("命令行输出失败: " + ex.Message); }
            return 0;
        }

        private static void RunCliCore(string mode, StringBuilder b)
        {
            b.AppendLine("SmoothWin 命令行模式: " + mode + "    " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            b.AppendLine("管理员: " + Trimmer.IsAdmin + "    数据目录: " + Config.Dir);
            b.AppendLine();

            if (mode == "trim")
            {
                Config cfg = TrayApp.LoadConfig();
                TrimResult r = Trimmer.Run(cfg, "命令行", false);
                b.AppendLine("整理进程 : " + r.Trimmed + " 个成功, " + r.Failed + " 个失败");
                b.AppendLine("主动跳过 : " + r.SkippedUsing + " 个（有窗口在用）, " + r.SkippedBusy + " 个（正在跑任务）, " + r.SkippedRecent + " 个（冷却期内）");
                b.AppendLine("可用内存 : " + r.BeforeAvailMB + " MB -> " + r.AfterAvailMB + " MB  (" + r.FreedMB.ToString("+#;-#;0") + " MB)");
                Sample s = Sample.Take();
                b.AppendLine("整理后   : 提交 " + s.CommitMB + "/" + s.CommitLimitMB + " MB (" + s.CommitPct + "%)  可用 " + s.AvailMB + " MB");
            }
            else if (mode == "report")
            {
                // 必须走 LoadConfig()（读 ini 后再按本机物理内存套自适应），
                // 否则在别的机器上会拿 ini 里的原始数字当阈值 —— 报告与实际行为两套值。
                Config cfg = TrayApp.LoadConfig();
                // 进程级 CPU 与磁盘速率都靠「两次采样的差值」，只采一次必然是空的；
                // 常驻实例本来就在每 5 秒采一次，命令行这种一次性进程必须先预热。
                // 预热两轮（共约 3 秒）：第一轮的窗口里全是这个进程自己的冷启动
                // （加载 .NET、初始化性能计数器都很吃 CPU），会得出 90% 这种
                // 看着吓人、其实是被自己污染的读数。第二轮才是干净窗口。
                Sample.Take();
                System.Threading.Thread.Sleep(1500);
                Sample.Take();
                System.Threading.Thread.Sleep(1500);
                TrayApp tmp = null;
                try { tmp = new TrayApp(true); b.Append(tmp.BuildReport()); }
                finally { if (tmp != null) tmp.ShutdownForCli(); }
            }
            else if (mode == "selftest")
            {
                b.AppendLine("--- 自检 ---");
                Sample s = Sample.Take();
                b.AppendLine("GlobalMemoryStatusEx : " + (s.TotalMB > 0 ? "OK 总 " + s.TotalMB + " MB" : "失败"));
                b.AppendLine("性能计数器           : " + (s.PoolNonPagedMB >= 0 ? "OK 非分页池 " + s.PoolNonPagedMB + " MB" : "不可用"));
                b.AppendLine("进程枚举             : OK " + s.Procs + " 个进程 / " + s.Threads + " 线程 / " + s.Handles + " 句柄");
                b.AppendLine("事件日志读取         : " + (Events.Count("Display", 4101, 720) >= 0 ? "OK 近30天 TDR " + Events.Count("Display", 4101, 720) + " 次" : "失败"));
                b.AppendLine("注册表读取           : " + (Reg.Get(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled") != null ? "OK" : "失败"));
                b.AppendLine("数据目录可写         : OK " + Config.Dir);
                IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION | Native.PROCESS_SET_QUOTA, false, Process.GetCurrentProcess().Id);
                b.AppendLine("OpenProcess 自身     : " + (h != IntPtr.Zero ? "OK" : "失败"));
                if (h != IntPtr.Zero) { b.AppendLine("EmptyWorkingSet 自身 : " + (Native.EmptyWorkingSet(h) ? "OK" : "失败")); Native.CloseHandle(h); }
                b.AppendLine("管理员权限           : " + (Trimmer.IsAdmin ? "有" : "无（整理他人进程会失败，属正常）"));
                IntPtr hio = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION | Native.PROCESS_QUERY_INFORMATION, false, Process.GetCurrentProcess().Id);
                bool ioOk = false;
                if (hio != IntPtr.Zero)
                {
                    Native.IO_COUNTERS ioc;
                    ioOk = Native.GetProcessIoCounters(hio, out ioc);
                    Native.CloseHandle(hio);
                }
                b.AppendLine("进程磁盘 IO 计数     : " + (ioOk ? "OK" : "失败（磁盘型提醒将只报总量）"));
            }
            else if (mode == "fix")
            {
                b.AppendLine("--- 应用系统优化 ---");
                b.Append(SystemFix.Apply());
            }
            else if (mode == "restore")
            {
                b.AppendLine("--- 还原系统优化 ---");
                b.Append(SystemFix.Restore());
            }
            else if (mode == "status")
            {
                b.AppendLine("--- 系统优化项 ---");
                b.Append(SystemFix.StatusText());
            }
            else if (mode == "install")
            {
                b.AppendLine("--- 启用开机自启 ---");
                b.AppendLine(Reg.SetAutoStart(true));
            }
            else if (mode == "uninstall")
            {
                b.AppendLine("--- 关闭开机自启 ---");
                b.AppendLine(Reg.SetAutoStart(false));
            }
            else if (mode == "devices")
            {
                b.AppendLine("--- 有问题的设备 ---");
                List<BadDevice> all = Devices.Scan();
                int hit = 0;
                foreach (BadDevice d in all) if (Devices.IsLikelyCause(d)) hit++;
                b.AppendLine("异常设备总数 : " + all.Count + "    可能有影响的 : " + hit);
                b.AppendLine("摘要         : " + Devices.Summary());
                b.AppendLine();
                if (hit > 0) { b.AppendLine(Devices.Advice()); b.AppendLine(); }
                b.AppendLine("--- 全部异常设备 ---");
                foreach (BadDevice d in all)
                {
                    b.AppendLine((Devices.IsLikelyCause(d) ? "[影响] " : "[忽略] ") + d.Display + "  ——  " + d.MeaningShort);
                    b.AppendLine("        " + d.Instance);
                }
                b.AppendLine();
                b.AppendLine("--- 挂起重启 ---");
                b.AppendLine(Reg.RebootPending() ? "有改动要重启后才生效" : "没有挂起的重启项");
                b.AppendLine("已连续运行 " + (Sample.Take().UptimeHours / 24).ToString("0.0") + " 天");
            }
            else if (mode == "startup")
            {
                b.AppendLine("--- 开机自启项 ---");
                b.Append(Startup.Text());
            }
            else if (mode == "settingshot")
            {
                // 设置窗口自检 + 截图：验证「自动」勾选框、数字框联动、以及
                // 保存后 ini 里写的是 auto 还是固定数字。截图用 PrintWindow 抓真实窗口，
                // 不依赖屏幕是否解锁。
                TrayApp app = new TrayApp(true);
                Config c0 = app.Cfg;
                b.AppendLine("物理内存          : " + app.Cfg.TotalPhysMB + " MB");
                b.AppendLine("自动模式(AutoTune): " + c0.AutoTune);
                b.AppendLine("UserSet 标志      : commit=" + c0.UserSetCommit + " comp=" + c0.UserSetComp + " minTrim=" + c0.UserSetMinTrim);
                b.AppendLine("当前生效阈值      : 提交 " + c0.CommitThresholdPct + "% / 压缩 " + c0.CompressionThresholdMB
                            + " MB / 整理下限 " + c0.MinTrimMB + " MB");
                b.AppendLine("按容量应算得      : 提交 " + Config.TunedCommitPct(c0.TotalPhysMB) + "% / 压缩 "
                            + Config.TunedCompressionMB(c0.TotalPhysMB) + " MB / 整理下限 "
                            + Config.TunedMinTrimMB(c0.TotalPhysMB) + " MB / 非分页池告警线 "
                            + c0.TunedPoolNonPagedMB() + " MB");
                b.AppendLine();

                SettingsForm sf = new SettingsForm(app);
                sf.Show();
                Application.DoEvents();
                System.Threading.Thread.Sleep(400);
                Application.DoEvents();

                // 先量一下窗体自身的尺寸，再决定位图开多大 —— 直接用 GetWindowRect 在
                // 某些环境（会话被锁、DPI 虚拟化）会拿到不合常理的矩形，截出一张
                // 大片空白的图。这里以控件实测尺寸为准。
                Rectangle rc;
                IntPtr hwnd = sf.Handle;
                bool rectOk = Native.GetWindowRect(hwnd, out rc);
                b.AppendLine("窗口矩形          : GetWindowRect=" + (rectOk ? "OK" : "FAIL")
                            + "  L=" + rc.Left + " T=" + rc.Top + " R=" + rc.Right + " B=" + rc.Bottom
                            + "  (W=" + (rc.Right - rc.Left) + " H=" + (rc.Bottom - rc.Top) + ")");
                b.AppendLine("窗体尺寸          : Width=" + sf.Width + " Height=" + sf.Height
                            + "  Client=" + sf.ClientSize.Width + "x" + sf.ClientSize.Height
                            + "  Visible=" + sf.Visible + "  屏幕=" + Screen.PrimaryScreen.Bounds.Width + "x" + Screen.PrimaryScreen.Bounds.Height);

                string shot = Path.Combine(Config.Dir, "settings-preview.png");
                int w = Math.Max(1, sf.Width), h = Math.Max(1, sf.Height);
                try
                {
                    using (Bitmap bmp = new Bitmap(w, h))
                    {
                        using (Graphics g = Graphics.FromImage(bmp))
                        {
                            g.Clear(Color.White);
                            IntPtr hdc = g.GetHdc();
                            Native.PrintWindow(hwnd, hdc, 2);
                            g.ReleaseHdc(hdc);
                        }
                        bmp.Save(shot, System.Drawing.Imaging.ImageFormat.Png);
                    }
                    b.AppendLine("截图              : " + shot + "  (" + w + "x" + h + ")");
                }
                catch (Exception ex) { b.AppendLine("截图失败          : " + ex.Message); }

                // PrintWindow 拿不到内容时的兜底：DrawToBitmap 走 WM_PRINT，
                // 有些被锁的会话里这条路径反而能画出控件。
                string shot2 = Path.Combine(Config.Dir, "settings-preview2.png");
                try
                {
                    using (Bitmap bmp = new Bitmap(w, h))
                    {
                        sf.DrawToBitmap(bmp, new Rectangle(0, 0, w, h));
                        bmp.Save(shot2, System.Drawing.Imaging.ImageFormat.Png);
                    }
                    b.AppendLine("兜底截图          : " + shot2 + "  (" + w + "x" + h + ")");
                }
                catch (Exception ex) { b.AppendLine("兜底截图失败      : " + ex.Message); }

                b.AppendLine();
                b.AppendLine("--- 自动勾选框联动测试 ---");
                b.AppendLine("初始：" + sf.DumpForTest());
                sf.SetAutoForTest(false, false, false);
                b.AppendLine("全取消后：" + sf.DumpForTest());
                sf.SetAutoForTest(true, true, true);
                b.AppendLine("全勾上后：" + sf.DumpForTest());
                sf.SaveForTest();
                Config c1 = Config.Load();
                b.AppendLine("保存后 ini 读回    : 提交=" + c1.CommitThresholdPct + " comp=" + c1.CompressionThresholdMB
                            + " min=" + c1.MinTrimMB + "  UserSet=" + c1.UserSetCommit + "/" + c1.UserSetComp + "/" + c1.UserSetMinTrim);
                // 上面那行的数字是「类字段默认值」而不是 ini 里的数：ini 写的是 auto，
                // 真正的生效值要套一遍自适应才知道。两行都打出来，免得看的人以为保存错了。
                c1.ApplyAutoTune(c0.TotalPhysMB);
                b.AppendLine("保存后实际生效    : 提交 " + c1.CommitThresholdPct + "% / 压缩 " + c1.CompressionThresholdMB
                            + " MB / 整理下限 " + c1.MinTrimMB + " MB   （换机器会按新内存重算）");
                b.AppendLine("ini 原文          : " + string.Join(" | ", File.ReadAllLines(Config.ConfigPath)));
                sf.Close();
            }
            else if (mode == "quit")
            {
                // 命令行退出：置起退出请求事件，让正在运行的实例自己走「手动退出」路径。
                // 特意不做成「直接杀进程」——那样测的是 taskkill，不是用户点退出的真实路径。
                IntPtr h = Native.CreateEventW(IntPtr.Zero, false, false, QuitMark.ExitEventName());
                if (h == IntPtr.Zero) b.AppendLine("创建退出事件失败: Win32 错误 " + Marshal.GetLastWin32Error());
                else
                {
                    Native.SetEvent(h);
                    Native.CloseHandle(h);
                    b.AppendLine("已发出退出请求（运行中的实例会按「手动退出」处理）");
                }
                b.AppendLine("退出记录(QuitMark) : " + (QuitMark.Pending() ? "存在 → 自启拉起的实例会静默退出" : "不存在 → 自启会正常拉起"));
                b.AppendLine("自启任务模板       : " + Reg.QueryAutoArg());
            }
            else if (mode == "clearmark")
            {
                // 测试/维护用：清掉「手动退出」记录（等于用户主动启动了一次）
                b.AppendLine("清除退出记录: " + (QuitMark.Consume() ? "已清除（原本存在）" : "本来就没有"));
            }
            else if (mode == "quitstate")
            {
                b.AppendLine("退出记录(QuitMark) : " + (QuitMark.Pending() ? "存在 → 自启拉起的实例会静默退出（用户已手动退出）" : "不存在 → 自启会正常拉起"));
                b.AppendLine("自启任务模板       : " + Reg.QueryAutoArg());
                string held = "未找到（没有实例在运行）";
                try
                {
                    using (Mutex m = Mutex.OpenExisting("SmoothWinTray_SingleInstance"))
                    {
                        // WaitOne 成功是真的拿到锁了，必须还回去：直接 Dispose 会把它变成
                        // 「已放弃」状态，紧接着启动的新实例就会看到「已存在但拿不到」而静默退出。
                        if (m.WaitOne(0)) { held = "被占用（有实例在运行）"; try { m.ReleaseMutex(); } catch { } }
                        else held = "空闲（没有实例在运行）";
                    }
                }
                catch { }
                b.AppendLine("单实例锁           : " + held);
            }
            else if (mode == "startupshot")
            {
                // 自启项窗口截图（给用户看「表格长什么样」）+ 权限说明。
                // 用 DrawToBitmap 而不是 PrintWindow：锁定/后台会话里 PrintWindow 会截出黑图。
                TrayApp app = new TrayApp(true);
                StartupForm f = new StartupForm(app);
                f.Show();
                Application.DoEvents();
                System.Threading.Thread.Sleep(700);
                Application.DoEvents();
                b.AppendLine("管理员=" + Trimmer.IsAdmin + "  进程完整性=" + Startup.CurrentIntegrity());
                b.Append(f.DumpForTest());
                ShotForm(f, Path.Combine(Config.Dir, "startup-preview.png"), b);
                f.Close();
            }
            else if (mode == "statusshot")
            {
                // 状态窗口截图：给用户看「改版后长什么样」。
                // 用 DrawToBitmap 而不是 PrintWindow：锁定/后台会话里 PrintWindow 会截出黑图。
                TrayApp app = new TrayApp(true);
                StatusForm f = new StatusForm(app);
                f.Show();
                Application.DoEvents();
                bool got = f.Refresh1AndWait(20000);
                b.AppendLine("界面数据已填好 = " + got);
                Application.DoEvents();
                b.AppendLine("管理员=" + Trimmer.IsAdmin + "  进程完整性=" + Startup.CurrentIntegrity());
                b.Append(f.LayoutForTest());
                b.Append(f.DumpForTest());
                ShotForm(f, Path.Combine(Config.Dir, "status-preview.png"), b);
                f.Close();
            }
            else if (mode == "leaktest")
            {
                // 增长提醒忽略名单自检：把「用户说 node 别再提醒了」这条链路整个走一遍。
                // 全程写在 --testdir 指定的数据目录里，不动真实配置。
                TrayApp app = new TrayApp(true);
                Config c = app.Cfg;
                b.AppendLine("数据目录          : " + Config.Dir);
                b.AppendLine("初始忽略名单      : '" + c.LeakIgnoreNames + "'   自动静音阈值=" + c.LeakMuteAfter);
                b.AppendLine("node 是否被忽略   : " + c.IsLeakIgnored("node"));
                b.AppendLine();
                b.AppendLine("--- 气泡正文（node）---");
                b.AppendLine(TrayApp.LeakBalloonText("node", false));
                b.AppendLine("--- 气泡正文（最后一次）---");
                b.AppendLine(TrayApp.LeakBalloonText("node", true));
                b.AppendLine();
                b.AppendLine("--- 点气泡加入忽略名单 ---");
                c.AddLeakIgnore("node");
                c.AddLeakIgnore("NODE");       // 大小写不同，不该重复加
                c.AddLeakIgnore("chrome");
                c.Save();
                b.AppendLine("内存里            : '" + c.LeakIgnoreNames + "'");
                Config c2 = Config.Load();
                b.AppendLine("重新读回 ini      : '" + c2.LeakIgnoreNames + "'");
                b.AppendLine("node 是否被忽略   : " + c2.IsLeakIgnored("node") + "（应为 True）");
                b.AppendLine("NODE 是否被忽略   : " + c2.IsLeakIgnored("NODE") + "（应大小写不敏感 = True）");
                b.AppendLine("nodejs 是否被忽略 : " + c2.IsLeakIgnored("nodejs") + "（应 False，不能误伤同名前缀）");
                b.AppendLine("firefox 是否被忽略: " + c2.IsLeakIgnored("firefox") + "（应 False）");
                b.AppendLine();
                b.AppendLine("--- 自动静音（同一个程序提醒够 LeakMuteAfter 次就自己闭嘴）---");
                Config c3 = Config.Load();
                for (int i = 1; i <= Math.Max(1, c3.LeakMuteAfter) + 1; i++)
                {
                    bool muted = c3.LeakMuteAfter > 0 && i >= c3.LeakMuteAfter;
                    if (muted) { c3.AddLeakIgnore("someapp"); c3.Save(); }
                    b.AppendLine("  第 " + i + " 次提醒 someapp → " + (muted ? "已自动静音并写进名单" : "照常提醒"));
                }
                Config c4 = Config.Load();
                b.AppendLine("静音后名单        : '" + c4.LeakIgnoreNames + "'");
                b.AppendLine("someapp 是否被忽略: " + c4.IsLeakIgnored("someapp") + "（应为 True）");
                b.AppendLine();
                b.AppendLine("--- 清空还原 ---");
                c4.LeakIgnoreNames = "";
                c4.Save();
                b.AppendLine("读回              : '" + Config.Load().LeakIgnoreNames + "'（应为空）");
            }
            else if (mode == "startupui")
            {
                // 自启项表格自检：内容 + 按钮位置 + 「启用/禁用」注册表往返（切一次再切回来）。
                TrayApp app = new TrayApp(true);
                StartupForm f = new StartupForm(app);
                f.Show();
                Application.DoEvents();
                b.Append(f.DumpForTest());
                b.AppendLine();
                b.AppendLine("--- 启用/禁用往返 ---");
                b.Append(f.ToggleRoundTripForTest());
                f.Close();
            }
            else if (mode == "apps")
            {
                // 后台应用的文本版：不开窗口，直接把「顶层程序 + 子进程」打成文字。
                // 给「想贴给别人看」或者不方便开界面的场合用（窗口版是 --appsui）。
                string note;
                List<AppNode> list = AppScan.Take(out note);
                AppScan.SortAll(list, AppScan.SortMem);
                b.AppendLine("管理员  : " + Trimmer.IsAdmin + "   进程完整性=" + Startup.CurrentIntegrity());
                b.AppendLine("顶层程序: " + list.Count + " 个   全部合计 " + AppScan.Mb(AppScan.TotalOf(list)));
                if (note.Length > 0) b.AppendLine("注意    : " + note);
                b.AppendLine();
                foreach (AppNode r in list)
                {
                    b.AppendLine(AppScan.RootText(r));
                    foreach (AppNode k in r.Kids) b.AppendLine("    " + AppScan.KidText(k));
                }
            }
            else if (mode == "appsui")
            {
                // 后台应用窗口自检：内容 + 按钮位置 + 真实地「起一个子进程再按 PID 关掉它」。
                TrayApp app = new TrayApp(true);
                AppForm f = new AppForm(app);
                f.Show();
                Application.DoEvents();
                System.Threading.Thread.Sleep(700);
                Application.DoEvents();
                b.Append(f.DumpForTest());
                b.AppendLine();
                b.AppendLine("--- 结束子进程实测（真起两个 ping，按 PID 关掉其中一个）---");
                b.Append(f.SelfTestKill());
                b.AppendLine();
                b.AppendLine("--- 排序 / 右键菜单实测 ---");
                b.Append(f.SelfTestExtras());
                f.Close();
            }
            else if (mode == "appsshot")
            {
                // 后台应用窗口截图（给用户看「进程树长什么样」）。
                // 用 DrawToBitmap 而不是 PrintWindow：锁定/后台会话里 PrintWindow 会截出黑图。
                TrayApp app = new TrayApp(true);
                AppForm f = new AppForm(app);
                f.Show();
                Application.DoEvents();
                System.Threading.Thread.Sleep(1200);
                Application.DoEvents();
                b.AppendLine("管理员=" + Trimmer.IsAdmin + "  进程完整性=" + Startup.CurrentIntegrity());
                b.Append(f.DumpForTest());
                ShotForm(f, Path.Combine(Config.Dir, "apps-preview.png"), b);
                f.Close();
            }
            else if (mode == "uicheck")
            {
                // 状态窗口自检：验证「点通知进来不再未响应」+ 卡片确实被填上数据。
                // 判据是 UI 心跳的最大停顿 —— 以前每秒钟被 BuildReport 堵 1.5 秒，
                // 心跳必然出现 >1000 毫秒的空档，Windows 就把窗口标成「未响应」。
                TrayApp app = new TrayApp(true);
                StatusForm f = new StatusForm(app);

                long t = Environment.TickCount;
                f.Show();
                Application.DoEvents();
                b.AppendLine("窗口 Show()        : " + (Environment.TickCount - t) + " ms");

                t = Environment.TickCount;
                f.Refresh1();
                b.AppendLine("Refresh1() 返回    : " + (Environment.TickCount - t) + " ms（应接近 0）");

                t = Environment.TickCount;
                app.ShowWindow();   // 等价于用户点通知气泡
                b.AppendLine("ShowWindow() 返回  : " + (Environment.TickCount - t) + " ms（应接近 0）");

                t = Environment.TickCount;
                app.BuildUiData();
                b.AppendLine("BuildUiData() 单次 : " + (Environment.TickCount - t) + " ms（在后台线程跑，堵不住界面）");

                // UI 心跳：8 秒内每 20 毫秒泵一次消息，记录最大间隔
                long last = Environment.TickCount, maxGap = 0, t0 = Environment.TickCount;
                while (Environment.TickCount - t0 < 8000)
                {
                    Application.DoEvents();
                    long now = Environment.TickCount;
                    if (now - last > maxGap) maxGap = now - last;
                    last = now;
                    System.Threading.Thread.Sleep(20);
                }
                b.AppendLine("UI 最大停顿        : " + maxGap + " ms（>1000 就是「未响应」）");
                b.AppendLine();
                b.AppendLine("--- 排版自检（按钮有没有被裁 / 页脚有没有被压住）---");
                b.Append(f.LayoutForTest());
                b.AppendLine();
                b.AppendLine("--- 界面上实际显示的内容 ---");
                b.Append(f.DumpForTest());
                b.AppendLine();
                b.AppendLine("--- 详细报告窗口（点开文字会不会被整段选中）---");
                using (DevForm df = new DevForm(app.BuildReport(), "SmoothWin 详细报告"))
                {
                    df.Show();
                    Application.DoEvents();
                    b.AppendLine("打开后      : " + df.SelectionForTest());
                    df.Activate();
                    Application.DoEvents();
                    System.Threading.Thread.Sleep(300);
                    Application.DoEvents();
                    b.AppendLine("激活后      : " + df.SelectionForTest());
                    b.AppendLine("窗口可见    : " + df.Visible + "   客户区=" + df.ClientSize.Width + "x" + df.ClientSize.Height);
                }
            }
            else
            {
                b.AppendLine("未知模式。可用: --trim / --report / --selftest / --fix / --restore / --status / --install / --uninstall / --devices / --startup / --apps / --uicheck / --settingshot / --startupui / --appsui / --appsshot / --startupshot / --statusshot / --leaktest / --quit / --quitstate / --clearmark");
            }
        }

        // 把一个窗体画进 PNG（只给命令行自检用）。
        // 优先 DrawToBitmap：它走 WM_PRINT，在会话被锁、窗口在后台时也画得出来；
        // PrintWindow 那种路径在锁定会话里会得到一张全黑的图（实测踩过）。
        private static void ShotForm(Form f, string path, StringBuilder b)
        {
            string target = path;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    f.Refresh();
                    Application.DoEvents();
                    int w = Math.Max(1, f.Width), h = Math.Max(1, f.Height);
                    using (Bitmap bmp = new Bitmap(w, h))
                    {
                        f.DrawToBitmap(bmp, new Rectangle(0, 0, w, h));
                        bmp.Save(target, System.Drawing.Imaging.ImageFormat.Png);
                    }
                    b.AppendLine("截图              : " + target + "  (" + w + "x" + h + ")");
                    return;
                }
                catch (Exception ex)
                {
                    // 第一次失败多半是旧 png 被占住或权限不给。删掉重试一次，
                    // 还是不行就换个带时间戳的新名字 —— 自检不能因为一个旧文件而假失败。
                    b.AppendLine("截图第 " + (attempt + 1) + " 次失败  : " + ex.Message);
                    try { File.Delete(target); } catch { }
                    if (attempt == 0)
                    {
                        try
                        {
                            string dir = Path.GetDirectoryName(path);
                            string name = Path.GetFileNameWithoutExtension(path)
                                + "-" + DateTime.Now.ToString("HHmmss") + Path.GetExtension(path);
                            target = (dir.Length > 0 ? Path.Combine(dir, name) : name);
                        }
                        catch { target = path; }
                    }
                }
            }
            b.AppendLine("截图失败          : 两次都没写成功（" + path + "）");
        }

        // 单实例互斥体的进程级引用。必须静态持有，因为「退出前先交锁」这个动作
        // 可能发生在别的线程（停摆看门狗）里，那里拿不到 Main 的局部变量。
        private static Mutex singleMutex;
        private static bool singleOwned;

        // 交出单实例锁。.NET 的 Application.ExitThread / Environment.Exit 都不会
        // 释放命名互斥体 —— 只要本进程还活着，别处创建同名互斥体拿到的就是「已存在」。
        // 主动退出（手动退出、假死自愈、切换管理员身份）前必须先交锁，
        // 否则紧接着启动的新实例会判定「已有实例在运行」而静默退出，托盘就彻底没了。
        internal static void ReleaseSingleInstance()
        {
            try { if (singleMutex != null && singleOwned) { singleMutex.ReleaseMutex(); singleOwned = false; } } catch { }
            try { if (singleMutex != null) { singleMutex.Dispose(); singleMutex = null; } } catch { }
        }

        [STAThread]
        private static void Main(string[] argv)
        {
            // --auto：由计划任务（开机自启 / 5 分钟自愈看门狗）拉起的实例。
            // 只有这种实例才需要尊重「用户手动退出」的记录；
            // 用户自己双击图标启动的实例一律照常启动。
            bool byAuto = false;
            if (argv != null && argv.Length > 0 && argv[0] == "--auto")
            {
                byAuto = true;
                string[] rest = new string[argv.Length - 1];
                Array.Copy(argv, 1, rest, 0, rest.Length);
                argv = rest;
            }

            // --testdir <目录>：把数据目录指到别处（自动化实测用，不碰真实配置）
            if (argv != null && argv.Length >= 2 && argv[0] == "--testdir")
            {
                Config.OverrideDir(argv[1]);
                string[] rest2 = new string[argv.Length - 2];
                Array.Copy(argv, 2, rest2, 0, rest2.Length);
                argv = rest2;
            }
            // --testexit <秒>：测试模式启动后 N 秒自动点一次「退出」
            if (argv != null && argv.Length >= 2 && argv[0] == "--testexit")
            {
                int secs = 0;
                int.TryParse(argv[1], out secs);
                Config.TestExitAfterSec = secs;
                string[] rest3 = new string[argv.Length - 2];
                Array.Copy(argv, 2, rest3, 0, rest3.Length);
                argv = rest3;
            }

            if (argv != null && argv.Length > 0 && argv[0].StartsWith("--") &&
                (argv[0] == "--trim" || argv[0] == "--report" || argv[0] == "--selftest" ||
                 argv[0] == "--fix" || argv[0] == "--restore" || argv[0] == "--status" ||
                 argv[0] == "--install" || argv[0] == "--uninstall" || argv[0] == "--devices" ||
                 argv[0] == "--startup" || argv[0] == "--uicheck" || argv[0] == "--settingshot" ||
                 argv[0] == "--leaktest" || argv[0] == "--startupshot" || argv[0] == "--statusshot" ||
                 argv[0] == "--quit" || argv[0] == "--quitstate" || argv[0] == "--clearmark" ||
                 argv[0] == "--startupui" || argv[0] == "--appsui" || argv[0] == "--appsshot" ||
                 argv[0] == "--apps"))
            {
                RunCli(argv);
                return;
            }

            Log.Write("=== 进程启动 ===  exe=" + Application.ExecutablePath + "  数据目录=" + Config.Dir
                + "  来源=" + (byAuto ? "自启计划任务" : "用户手动"));
            Log.Write("数据目录判定: " + Config.DirNotes);
            Log.Heartbeat("启动 pid=" + Process.GetCurrentProcess().Id + " 管理员=" + Trimmer.IsAdmin
                + " 来源=" + (byAuto ? "自启" : "手动") + " 数据目录=" + Config.Dir + "  " + Config.DirNotes);

            // 用户点过「退出」：自启拉起的实例直接静默退出，不复活。
            // 用户自己双击的实例照常启动（下面还会顺手把退出记录清掉）。
            if (byAuto && QuitMark.Pending())
            {
                Log.Write("检测到「用户手动退出」记录，本次为自启拉起，静默退出（不复活）");
                Log.Heartbeat("尊重手动退出，自启实例静默退出 pid=" + Process.GetCurrentProcess().Id);
                return;
            }

            // 互斥体创建必须包 try：权限不同的两个会话之间打开命名互斥体会抛
            // UnauthorizedAccessException，若不捕获会让进程「只写一行日志就静默消失」。
            bool created = false;
            try { singleMutex = new Mutex(true, "SmoothWinTray_SingleInstance", out created); singleOwned = created; }
            catch (Exception ex)
            {
                Log.Write("单实例互斥体不可用（" + ex.Message + "），本次启动静默退出");
                return;
            }

            try
            {
                // 自愈看门狗每 5 分钟会拉起一个实例：若正在运行的那个已经「假死」
                // （进程还在、心跳早就停了），这次触发就顺手把它杀掉再自己接管，
                // 否则看门狗永远被互斥体挡在门外，假死的进程没人处理。
                if (!created && TrayApp.IsHung())
                {
                    Log.Write("已有实例在运行但心跳停滞，判定为假死，接管启动");
                    Log.Heartbeat("假死接管 pid=" + Process.GetCurrentProcess().Id);
                    TrayApp.KillHung();
                    ReleaseSingleInstance();
                    singleMutex = new Mutex(true, "SmoothWinTray_SingleInstance", out created);
                    singleOwned = created;
                }
                if (!created)
                {
                    // 已在运行：静默退出（开机自启重复触发时不打扰用户）
                    Log.Write("已有实例在运行，本次启动静默退出");
                    Log.Heartbeat("已有实例在运行，本次启动静默退出 pid=" + Process.GetCurrentProcess().Id);
                    return;
                }

                // 走到这里 = 本实例真的接管了托盘。如果是用户自己启动的，
                // 先把「手动退出」记录清掉：否则下次自启拉起的实例还会以为用户已经退出了。
                if (!byAuto && QuitMark.Consume())
                    Log.Write("用户主动启动，已清除「手动退出」记录");
                if (!byAuto)
                {
                    string fix = Reg.EnsureTimerTrigger();
                    if (fix.Length > 0) Log.Write("自启任务检查: " + fix);
                }
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += delegate (object s, ThreadExceptionEventArgs e) { Log.Write("未处理异常: " + e.Exception.Message); };
                AppDomain.CurrentDomain.UnhandledException += delegate (object s, UnhandledExceptionEventArgs e) { Log.Write("致命异常: " + e.ExceptionObject); };
                // 首轮异常：只记「会让进程直接消失」的三类。普通异常每秒几十个，
                // 全记会把日志淹掉，反而看不见关键信息。
                try
                {
                    AppDomain.CurrentDomain.FirstChanceException += delegate (object s, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs e)
                    {
                        string n = e.Exception.GetType().FullName;
                        if (n == "System.StackOverflowException" || n == "System.AccessViolationException" || n == "System.OutOfMemoryException")
                            Log.Write("严重异常（首轮）: " + n + " :: " + e.Exception.Message);
                    };
                }
                catch { }
                try
                {
                    Log.Write("构造 TrayApp…");
                    TrayApp app = new TrayApp();
                    Log.Write("TrayApp 构造完成，进入消息循环");
                    Log.Heartbeat("进入消息循环 pid=" + Process.GetCurrentProcess().Id);
                    Application.Run(app);
                    Log.Write("消息循环结束");
                    Log.Heartbeat("消息循环结束 pid=" + Process.GetCurrentProcess().Id);
                }
                catch (Exception ex)
                {
                    Log.Write("Main 异常: " + ex.ToString());
                    MessageBox.Show(ex.ToString(), "SmoothWin 启动失败");
                }
            }
            finally
            {
                ReleaseSingleInstance();
            }
        }
    }
}
