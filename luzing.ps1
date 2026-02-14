# ============================================================================
# AUTO-ELEVATE TO ADMINISTRATOR
# ============================================================================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`""
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}
 
Clear-Host
 
# ============================================================================
# HEADER
# ============================================================================
$line1 = '=================================================='
$line2 = ' luzing SS analyzer v1.1 '
$line3 = ' base mod analyzer by Yarp - Upgraded by Luzing'
$line4 = 'Please only use if your trusted '
$line5 = 'Upgrade based on RedLotus/Doomsday/Prestige SS Data'
 
Write-Host $line1 -ForegroundColor Cyan
Write-Host $line2 -ForegroundColor Yellow
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
Write-Host $line3 -ForegroundColor Green
Write-Host $line4 -ForegroundColor Gray
Write-Host $line5 -ForegroundColor Gray
Write-Host ''
Write-Host "Luzing's analyzer v1.1 - Efficient" -ForegroundColor Cyan
Write-Host "Based used was Yarp Mod Analyzer" -ForegroundColor Gray
Write-Host "Made by using SSing data found on cheats" -ForegroundColor Gray
Write-Host ''
 
# ============================================================================
# MODS FOLDER PATH
# ============================================================================
$prompt1 = 'Enter path to the mods folder: '
$prompt2 = '(press Enter to use default)'
Write-Host $prompt1 -NoNewline
Write-Host $prompt2 -ForegroundColor DarkGray
$mods = Read-Host 'PATH'
Write-Host ''
 
if (-not $mods) {
    $mods = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    $defaultMsg = "Using default path: $mods"
    Write-Host $defaultMsg -ForegroundColor White
    Write-Host ''
}
 
if (-not (Test-Path $mods -PathType Container)) {
    $invalidMsg = 'Invalid Path!'
    Write-Host $invalidMsg -ForegroundColor Red
    exit 1
}
 
# ============================================================================
# MINECRAFT UPTIME CHECK
# ============================================================================
$process = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $process) { $process = Get-Process java -ErrorAction SilentlyContinue }
 
if ($process) {
    try {
        $elapsedTime = (Get-Date) - $process.StartTime
        $uptimeMsg = "Minecraft Uptime: $($process.Name) PID $($process.Id) started at $($process.StartTime) and running for $($elapsedTime.Hours)h $($elapsedTime.Minutes)m $($elapsedTime.Seconds)s"
        Write-Host $uptimeMsg -ForegroundColor Cyan
        Write-Host ''
    } catch {}
}
 
# ============================================================================
# JVM ARGUMENTS INJECTION SCANNER (with whitelist)
# ============================================================================
Write-Host $line1 -ForegroundColor Yellow
$header1 = 'JVM ARGUMENTS INJECTION SCANNER'
Write-Host $header1 -ForegroundColor Yellow
Write-Host $line1 -ForegroundColor Yellow
Write-Host ''
 
$javaProcesses = Get-Process -Name javaw -ErrorAction SilentlyContinue
 
if ($javaProcesses.Count -eq 0) {
    $msg1 = '  [i] No javaw.exe processes found'
    $msg2 = '  [i] Make sure Minecraft is running'
    Write-Host $msg1 -ForegroundColor Yellow
    Write-Host $msg2 -ForegroundColor Yellow
    Write-Host ''
} else {
    $scanMsg = "  [i] Scanning $($javaProcesses.Count) Java process(es)..."
    Write-Host $scanMsg -ForegroundColor White
    Write-Host ''
 
    $foundInjection = $false
    $whitelist = @('thesus.jar', 'idea_rt.jar', 'jacocoagent.jar', 'jmcagent.jar', 'async-profiler.jar')
 
    foreach ($proc in $javaProcesses) {
        try {
            $wmiProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop
            $commandLine = $wmiProcess.CommandLine
 
            if ($commandLine) {
                $procMsg = "  Process: PID $($proc.Id) - $($proc.ProcessName)"
                Write-Host $procMsg -ForegroundColor Green
 
                # Extract ALL -javaagent entries
                $agentMatches = [regex]::Matches($commandLine, '-javaagent:([^\s]+)')
                if ($agentMatches.Count -gt 0) {
                    foreach ($match in $agentMatches) {
                        $agentPath = $match.Groups[1].Value
                        $agentName = Split-Path $agentPath -Leaf
 
                        $pathMsg = "    Agent path: $agentPath"
                        Write-Host $pathMsg -ForegroundColor Gray
 
                        if ($whitelist -contains $agentName) {
                            $legitMsg = "      [+] LEGITIMATE: $agentName (whitelisted)"
                            Write-Host $legitMsg -ForegroundColor Green
                        } else {
                            $unknownMsg = "      [!] UNKNOWN AGENT: $agentName (possible cheat)"
                            Write-Host $unknownMsg -ForegroundColor Red
                            $foundInjection = $true
                        }
                    }
                } else {
                    $noAgentMsg = '    No Java agents found'
                    Write-Host $noAgentMsg -ForegroundColor Green
                }
 
                # Check for other injection flags
                if ($commandLine -match '-Dfabric\.addMods=' -or $commandLine -match '-Dfml\.coreMods\.load=' -or $commandLine -match '-Dforge\.mods=') {
                    $forgeMsg = '    [!] FABRIC/FORGE INJECTION DETECTED'
                    Write-Host $forgeMsg -ForegroundColor Red
                    $foundInjection = $true
                }
 
                Write-Host ''
            }
        } catch {
            $errorMsg = "  Could not access command line for PID $($proc.Id)"
            Write-Host $errorMsg -ForegroundColor Gray
            Write-Host ''
        }
    }
 
    if (-not $foundInjection) {
        $noInjectMsg = '  [i] No JVM argument injection detected.'
        Write-Host $noInjectMsg -ForegroundColor Green
        Write-Host ''
    }
}
 
# ============================================================================
# MODS FOLDER TAMPERING CHECK
# ============================================================================
Write-Host $line1 -ForegroundColor Yellow
$header2 = 'MODS FOLDER TAMPERING CHECK'
Write-Host $header2 -ForegroundColor Yellow
Write-Host $line1 -ForegroundColor Yellow
Write-Host ''
 
$modsFolder = Get-Item $mods
$modsModified = $modsFolder.LastWriteTime
$timeSinceModsChange = (Get-Date) - $modsModified
 
$modTimeMsg = "Mods folder last modified: $modsModified"
$timeChangeMsg = "Time since change: $($timeSinceModsChange.Hours)h $($timeSinceModsChange.Minutes)m $($timeSinceModsChange.Seconds)s"
Write-Host $modTimeMsg -ForegroundColor White
Write-Host $timeChangeMsg -ForegroundColor White
 
if ($timeSinceModsChange.TotalMinutes -lt 15) {
    $warn1 = '!!! WARNING: Mods folder modified within last 15 minutes !!!'
    $warn2 = '    This is during your screenshare session.'
    $warn3 = '    Strong indicator of tampering/self-destruct.'
    Write-Host $warn1 -ForegroundColor Red
    Write-Host $warn2 -ForegroundColor Red
    Write-Host $warn3 -ForegroundColor Red
} else {
    $cleanMods = 'Mods folder not recently tampered with'
    Write-Host $cleanMods -ForegroundColor Green
}
Write-Host ''
 
# ============================================================================
# CHEAT STRING DETECTION (Binary scan of mods folder)
# ============================================================================
Write-Host $line1 -ForegroundColor Magenta
$header3 = 'CHEAT STRING DETECTION (Binary Scan)'
Write-Host $header3 -ForegroundColor Magenta
Write-Host $line1 -ForegroundColor Magenta
Write-Host ''
 
$cheatStrings = @(
    'Doomsday',
    'prestige',
    'psaclient',
    '198m',
    'Auto Crystal',
    'Anchor Macro',
    'fastplace',
    'Self Destruct',
    'Aimbot'
)
 
$jarFiles = Get-ChildItem -Path $mods -Filter '*.jar' -File
 
if ($jarFiles.Count -eq 0) {
    $noJars = 'No .jar files found in mods folder.'
    Write-Host $noJars -ForegroundColor Yellow
    Write-Host ''
} else {
    foreach ($jar in $jarFiles) {
        $scanning = "Scanning: $($jar.Name)"
        Write-Host $scanning -NoNewline
        $found = $false
 
        try {
            $bytes = [System.IO.File]::ReadAllBytes($jar.FullName)
            $content = [System.Text.Encoding]::ASCII.GetString($bytes)
 
            foreach ($string in $cheatStrings) {
                if ($content.Contains($string)) {
                    if (-not $found) { 
                        Write-Host '' 
                        $found = $true 
                    }
                    $foundMsg = "  [!] FOUND: $string"
                    Write-Host $foundMsg -ForegroundColor Red
                }
            }
 
            if (-not $found) {
                $clean = ' - Clean'
                Write-Host $clean -ForegroundColor Green
            }
        } catch {
            $errorRead = ' - Error reading file'
            Write-Host $errorRead -ForegroundColor Yellow
        }
    }
    Write-Host ''
}
 
# ============================================================================
# MEMORY SCANNER WITH FILTERED REGIONS (Mapped + Private only)
# ============================================================================
Write-Host $line1 -ForegroundColor Magenta
$headerMem = 'TARGETED MEMORY SCANNER (Mapped+Private)'
Write-Host $headerMem -ForegroundColor Magenta
Write-Host $line1 -ForegroundColor Magenta
Write-Host ''
 
# C# memory scanner with region type filtering
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
 
public class MemoryScanner
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
 
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out uint lpNumberOfBytesRead);
 
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
 
    [DllImport("kernel32.dll")]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
 
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
 
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_MAPPED = 0x40000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_EXECUTE_READ = 0x20;
 
    public static bool ScanProcess(int pid, string[] needles, Action<string> outputCallback)
    {
        bool foundAny = false;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            outputCallback("  [!] Failed to open process (try running as Administrator)");
            return false;
        }
 
        try
        {
            IntPtr address = IntPtr.Zero;
            while (true)
            {
                MEMORY_BASIC_INFORMATION mbi;
                int result = VirtualQueryEx(hProcess, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
 
                if (result == 0) break;
 
                // Check if memory is committed and readable AND region type is IMAGE or PRIVATE (mapped+private)
                if (mbi.State == MEM_COMMIT && 
                    (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READ) &&
                    (mbi.Type == MEM_IMAGE || mbi.Type == MEM_PRIVATE))
                {
                    long regionSize = (long)mbi.RegionSize;
                    long offset = 0;
                    const int chunkSize = 1024 * 1024; // 1 MB chunks
 
                    while (offset < regionSize)
                    {
                        int bytesToRead = (int)Math.Min(chunkSize, regionSize - offset);
                        byte[] buffer = new byte[bytesToRead];
                        uint bytesRead;
 
                        long baseAddrLong = mbi.BaseAddress.ToInt64();
                        IntPtr readAddress = new IntPtr(baseAddrLong + offset);
 
                        if (ReadProcessMemory(hProcess, readAddress, buffer, (uint)bytesToRead, out bytesRead) && bytesRead > 0)
                        {
                            string regionText = Encoding.ASCII.GetString(buffer, 0, (int)bytesRead);
 
                            foreach (string needle in needles)
                            {
                                if (regionText.Contains(needle))
                                {
                                    outputCallback(needle);
                                    foundAny = true;
                                }
                            }
                        }
                        offset += bytesToRead;
                    }
                }
 
                long nextAddrLong = mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize;
                address = new IntPtr(nextAddrLong);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
        return foundAny;
    }
}
"@ -ErrorAction SilentlyContinue
 
# Trimmed pattern list: only Prestige, Doomsday, and the specific 198m string
$cheatPatterns = @{
    'Prestige' = @(
        'prestigeclient.vip',
        '.prestigeclient.vip0',
        'prestige_4.properties',
        'assets/minecraft/optifine/cit/profile/prestige/',
        'prestigeclient.vip0Y0',
        'prestige'
    )
    'Doomsday' = @(
        'Doomsday',
        'DoomsdayClient',
        'DoomsdayClient:::bot),%.R',
        'DoomsdayClient:::u;<r,7NVce;Ga25',
        'DoomsdayClient:::eObOiPdFJR 2',
        'DoomsdayClient:::Wu&XNC]30?3=7'
    )
    'GenericModules' = @(
        '198m'
    )
}
 
$javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
 
if ($javaw) {
    Write-Host "  Scanning javaw.exe PID $($javaw.Id) for targeted cheat patterns..." -ForegroundColor White
    $foundInMemory = $false
 
    # Build reverse lookup: string -> cheat name
    $stringToCheat = @{}
    foreach ($cheatName in $cheatPatterns.Keys) {
        foreach ($s in $cheatPatterns[$cheatName]) {
            $stringToCheat[$s] = $cheatName
        }
    }
 
    $allStrings = $stringToCheat.Keys | Sort-Object -Unique
    $reportedStrings = [System.Collections.Generic.HashSet[string]]::new()
 
    try {
        $result = [MemoryScanner]::ScanProcess($javaw.Id, $allStrings, {
            param($foundString)
            if (-not $script:reportedStrings.Contains($foundString)) {
                $script:reportedStrings.Add($foundString) | Out-Null
                $cheatName = $script:stringToCheat[$foundString]
                Write-Host "    [!] FOUND: $cheatName (string: $foundString)" -ForegroundColor Red
                $script:foundInMemory = $true
            }
        })
    } catch {
        Write-Host "  [!] Memory scanner error: $_" -ForegroundColor Red
    }
 
    if (-not $foundInMemory) {
        Write-Host '  [+] No known cheat strings found in memory' -ForegroundColor Green
    }
} else {
    Write-Host '  [!] javaw.exe not running' -ForegroundColor Yellow
}
Write-Host ''
 
# ============================================================================
# OBFUSCATION DETECTION
# ============================================================================
Write-Host $line1 -ForegroundColor DarkYellow
$header4 = 'OBFUSCATION DETECTION'
Write-Host $header4 -ForegroundColor DarkYellow
Write-Host $line1 -ForegroundColor DarkYellow
Write-Host ''
 
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
 
$jarFiles = Get-ChildItem -Path $mods -Filter '*.jar' -File
 
if ($jarFiles.Count -eq 0) {
    $noJars = 'No .jar files found in mods folder.'
    Write-Host $noJars -ForegroundColor Yellow
    Write-Host ''
} else {
    foreach ($jar in $jarFiles) {
        $obfuscationScore = 0
        $reasons = @()
 
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)
 
            $singleCount = 0
            $twoCount = 0
            $numberedCount = 0
            $totalClasses = 0
 
            foreach ($entry in $zip.Entries) {
                if ($entry.Name -match '\.class$') {
                    $totalClasses++
 
                    if ($entry.Name -match '^[a-zA-Z]\.class$') { 
                        $singleCount++ 
                    }
 
                    if ($entry.Name -match '^[a-zA-Z]{2}\.class$') { 
                        $twoCount++ 
                    }
 
                    if ($entry.Name -match '^\d+\.class$') { 
                        $numberedCount++ 
                    }
                }
            }
 
            $zip.Dispose()
 
            if ($totalClasses -lt 10) {
                continue
            }
 
            if ($numberedCount -gt 5) {
                $obfuscationScore += 3
                $reasons += "$numberedCount numbered classes - PRESTIGE PATTERN"
            }
 
            if ($singleCount -gt 5) {
                $obfuscationScore += 2
                $reasons += "$singleCount single-letter classes"
            }
 
            if ($twoCount -gt 20) {
                $obfuscationScore += 1
                $reasons += "$twoCount two-letter classes"
            }
 
            if ($obfuscationScore -ge 3) {
                $heavyMsg = "$($jar.Name): RED - HEAVILY OBFUSCATED"
                Write-Host $heavyMsg -ForegroundColor Red
                foreach ($reason in $reasons) { 
                    $reasonMsg = "  - $reason"
                    Write-Host $reasonMsg -ForegroundColor Red 
                }
            } elseif ($obfuscationScore -ge 1) {
                $maybeMsg = "$($jar.Name): YELLOW - Possibly obfuscated"
                Write-Host $maybeMsg -ForegroundColor Yellow
                foreach ($reason in $reasons) { 
                    $reasonMsg = "  - $reason"
                    Write-Host $reasonMsg -ForegroundColor Yellow 
                }
            }
        } catch {
            $errorJar = "$($jar.Name): Error reading file"
            Write-Host $errorJar -ForegroundColor Gray
        }
    }
    Write-Host ''
}
 
# ============================================================================
# DOWNLOAD ORIGIN CHECK (Zone.Identifier)
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
$header5 = 'DOWNLOAD ORIGIN CHECK'
Write-Host $header5 -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
 
$jarFiles = Get-ChildItem -Path $mods -Filter '*.jar' -File
$foundZone = $false
 
foreach ($jar in $jarFiles) {
    $zonePath = $jar.FullName + ':Zone.Identifier'
    if (Test-Path $zonePath) {
        $foundZone = $true
        $dlMsg = "$($jar.Name): Downloaded from internet"
        Write-Host $dlMsg -ForegroundColor Yellow
    }
}
 
if (-not $foundZone) {
    $noZone = 'No Zone.Identifier streams found (files were extracted/moved).'
    Write-Host $noZone -ForegroundColor Gray
}
Write-Host ''
 
# ============================================================================
# UNLOADED MOD DETECTION (manual reminder)
# ============================================================================
Write-Host $line1 -ForegroundColor Red
$header6 = 'UNLOADED MOD DETECTION (Manual Check)'
Write-Host $header6 -ForegroundColor Red
Write-Host $line1 -ForegroundColor Red
Write-Host ''
 
$javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
 
if ($javaw) {
    $manual1 = '!!! MANUAL STEP REQUIRED (if memory scanner missed something) !!!'
    Write-Host $manual1 -ForegroundColor Red
    Write-Host ''
    Write-Host '1. Open System Informer' -ForegroundColor White
    $pidMsg = "2. Right-click javaw.exe PID $($javaw.Id) - Properties - Memory - Strings"
    Write-Host $pidMsg -ForegroundColor White
    Write-Host '3. Set Min length: 5, select Mapped + Private' -ForegroundColor White
    Write-Host '4. Click Strings, then Filter' -ForegroundColor White
    Write-Host ''
    $filterMsg = "   Filter contains: $mods"
    Write-Host $filterMsg -ForegroundColor White
    Write-Host ''
    $selfDestructMsg = '   If you see .jar paths here that are NOT in your mods folder = SELF DESTRUCT'
    Write-Host $selfDestructMsg -ForegroundColor Red
    Write-Host ''
} else {
    $noJavaw = 'javaw.exe not running - cannot check for unloaded mods'
    Write-Host $noJavaw -ForegroundColor Red
    Write-Host ''
}
 
# ============================================================================
# EXECUTION EVIDENCE CHECK (PCA)
# ============================================================================
Write-Host $line1 -ForegroundColor DarkCyan
$header7 = 'EXECUTION EVIDENCE CHECK (PCA)'
Write-Host $header7 -ForegroundColor DarkCyan
Write-Host $line1 -ForegroundColor DarkCyan
Write-Host ''
 
$pcaPath = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
 
if (Test-Path $pcaPath) {
    $pcaEntries = Get-ItemProperty -Path $pcaPath -ErrorAction SilentlyContinue
    $pcaValues = $pcaEntries.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -First 10
 
    if ($pcaValues) {
        Write-Host '  Recently executed programs (PCA Store):' -ForegroundColor Yellow
        foreach ($entry in $pcaValues) {
            Write-Host "    $($entry.Name)" -ForegroundColor White
        }
    } else {
        Write-Host '  No execution entries found.' -ForegroundColor Gray
    }
} else {
    Write-Host '  PCA Store key not found.' -ForegroundColor Gray
}
Write-Host ''
 
# ============================================================================
# RECENTDOCS REGISTRY CHECK
# ============================================================================
Write-Host $line1 -ForegroundColor DarkCyan
$headerRecent = 'RECENTLY OPENED FILES (RecentDocs)'
Write-Host $headerRecent -ForegroundColor DarkCyan
Write-Host $line1 -ForegroundColor DarkCyan
Write-Host ''
 
$recentPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
if (Test-Path $recentPath) {
    $recentItems = Get-ChildItem $recentPath -ErrorAction SilentlyContinue
    $suspicious = @()
    foreach ($item in $recentItems) {
        $value = (Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue).'(default)'
        if ($value -and $value -match '\.(jar|exe|dll|bat|ps1|py|vbs)$') {
            $suspicious += $value
        }
    }
    if ($suspicious) {
        Write-Host '  [!] Suspicious recently opened files:' -ForegroundColor Red
        $suspicious | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    } else {
        Write-Host '  [+] No suspicious recent files.' -ForegroundColor Green
    }
} else {
    Write-Host '  RecentDocs key not found.' -ForegroundColor Gray
}
Write-Host ''
 
# ============================================================================
# USB DEVICE HISTORY CHECK (FIXED – with safe date handling and ASCII bullets)
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
$headerUSB = 'USB DEVICE HISTORY'
Write-Host $headerUSB -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
 
$usbPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
if (Test-Path $usbPath) {
    $deviceClasses = Get-ChildItem $usbPath -ErrorAction SilentlyContinue
    $allDevices = @()
    $recentDevices = @()
    $now = Get-Date
 
    foreach ($class in $deviceClasses) {
        $instances = Get-ChildItem $class.PSPath -ErrorAction SilentlyContinue
        foreach ($instance in $instances) {
            $props = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
            $friendlyName = $props.FriendlyName
            if (-not $friendlyName) { continue }  # Not a storage device
 
            # Safely get last write time as DateTime
            $lastConnected = $instance.LastWriteTime
            if ($lastConnected -isnot [DateTime]) {
                try {
                    $lastConnected = [DateTime]::Parse($lastConnected)
                } catch {
                    $lastConnected = $now  # fallback to now if parsing fails
                }
            }
 
            $firstConnected = $instance.CreationTime
            if ($firstConnected -isnot [DateTime]) {
                try {
                    $firstConnected = [DateTime]::Parse($firstConnected)
                } catch {
                    $firstConnected = $now
                }
            }
 
            $timeDiff = $now - $lastConnected
            $hoursAgo = [math]::Round($timeDiff.TotalHours, 1)
 
            $deviceInfo = [PSCustomObject]@{
                Name         = $friendlyName
                LastSeen     = $lastConnected
                FirstSeen    = $firstConnected
                HoursAgo     = $hoursAgo
                InstancePath = $instance.PSPath
            }
            $allDevices += $deviceInfo
 
            if ($hoursAgo -lt 24) {
                $recentDevices += $deviceInfo
            }
        }
    }
 
    if ($allDevices.Count -gt 0) {
        Write-Host "  USB storage devices ever connected: $($allDevices.Count)" -ForegroundColor White
 
        if ($recentDevices.Count -gt 0) {
            Write-Host '    [!] RECENT DEVICES (last 24h):' -ForegroundColor Yellow
            $recentDevices | Sort-Object LastSeen -Descending | ForEach-Object {
                Write-Host "      - $($_.Name)" -ForegroundColor Red
                Write-Host "        Last seen: $($_.LastSeen) ($($_.HoursAgo) hours ago)" -ForegroundColor Gray
            }
            Write-Host ''
        }
 
        # Show all unique device names (compact list)
        $uniqueNames = $allDevices | ForEach-Object { $_.Name } | Sort-Object -Unique
        Write-Host '    All detected USB storage devices (names):' -ForegroundColor Gray
        $uniqueNames | ForEach-Object { Write-Host "      - $_" -ForegroundColor Gray }
    } else {
        Write-Host '  No USB storage devices found in history.' -ForegroundColor Green
    }
} else {
    Write-Host '  USBSTOR registry key not found.' -ForegroundColor Gray
}
Write-Host ''
 
# ============================================================================
# SUMMARY
# ============================================================================
Write-Host $line1 -ForegroundColor Green
$summaryHeader = 'SCAN COMPLETE - LUZING ULTIMATE V1.1'
Write-Host $summaryHeader -ForegroundColor Green
Write-Host $line1 -ForegroundColor Green
Write-Host ''
 
$reminder1 = '!!! REMINDER: Prestige/Rise/Lambda may be memory-only !!!'
$reminder2 = '   The automated memory scanner above checks only Mapped+Private regions and specific strings.'
$reminder3 = '   If it found nothing but you suspect injection, use manual System Informer check.'
Write-Host $reminder1 -ForegroundColor Yellow
Write-Host $reminder2 -ForegroundColor Yellow
Write-Host $reminder3 -ForegroundColor Yellow
Write-Host ''
 
# ============================================================================
# EXIT – require typing "close"
# ============================================================================
do {
    $response = Read-Host 'Type "close" to exit'
} while ($response -ne 'close')
Clear-Host