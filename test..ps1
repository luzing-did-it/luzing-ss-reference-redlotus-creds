# ============================================================================
# LUZING'S ULTIMATE MINECRAFT SCREENSHARE ANALYZER
# ============================================================================
# Author: Luzing
# Version: 3.0 - "The Complete Package"
# ============================================================================

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`""
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

Clear-Host
$line1 = '=================================================='
$line2 = '     LUZING''S ULTIMATE SCREENSHARE ANALYZER     '
$line3 = '                  Version 3.0                     '
$line4 = '         "The Complete Package"                   '
Write-Host $line1 -ForegroundColor Cyan
Write-Host $line2 -ForegroundColor Yellow
Write-Host $line3 -ForegroundColor Yellow
Write-Host $line4 -ForegroundColor Red
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
Write-Host 'Created by Luzing' -ForegroundColor Green
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
    Write-Host "Using default path: $mods" -ForegroundColor White
    Write-Host ''
}

if (-not (Test-Path $mods -PathType Container)) {
    Write-Host 'Invalid Path!' -ForegroundColor Red
    exit 1
}

# ============================================================================
# MINECRAFT UPTIME CHECK
# ============================================================================
$process = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $process) { $process = Get-Process java -ErrorAction SilentlyContinue }
if ($process) {
    $elapsedTime = (Get-Date) - $process.StartTime
    Write-Host "Minecraft Uptime: $($process.Name) PID $($process.Id) started at $($process.StartTime) and running for $($elapsedTime.Hours)h $($elapsedTime.Minutes)m $($elapsedTime.Seconds)s" -ForegroundColor Cyan
    Write-Host ''
}

# ============================================================================
# JVM ARGUMENTS INJECTION SCANNER
# ============================================================================
Write-Host $line1 -ForegroundColor Yellow
Write-Host 'JVM ARGUMENTS INJECTION SCANNER' -ForegroundColor Yellow
Write-Host $line1 -ForegroundColor Yellow
Write-Host ''

$javaProcesses = Get-Process -Name javaw -ErrorAction SilentlyContinue
if ($javaProcesses.Count -eq 0) {
    Write-Host '  [i] No javaw.exe processes found' -ForegroundColor Yellow
    Write-Host '  [i] Make sure Minecraft is running' -ForegroundColor Yellow
    Write-Host ''
} else {
    Write-Host "  [i] Scanning $($javaProcesses.Count) Java process(es)..." -ForegroundColor White
    Write-Host ''
    $foundInjection = $false
    $whitelist = @('thesus.jar', 'idea_rt.jar', 'jacocoagent.jar', 'jmcagent.jar', 'async-profiler.jar')
    foreach ($proc in $javaProcesses) {
        try {
            $wmiProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop
            $commandLine = $wmiProcess.CommandLine
            if ($commandLine) {
                Write-Host "  Process: PID $($proc.Id) - $($proc.ProcessName)" -ForegroundColor Green
                $agentMatches = [regex]::Matches($commandLine, '-javaagent:([^\s]+)')
                if ($agentMatches.Count -gt 0) {
                    foreach ($match in $agentMatches) {
                        $agentPath = $match.Groups[1].Value
                        $agentName = Split-Path $agentPath -Leaf
                        Write-Host "    Agent path: $agentPath" -ForegroundColor Gray
                        if ($whitelist -contains $agentName) {
                            Write-Host "      [+] LEGITIMATE: $agentName (whitelisted)" -ForegroundColor Green
                        } else {
                            Write-Host "      [!] UNKNOWN AGENT: $agentName (possible cheat)" -ForegroundColor Red
                            $foundInjection = $true
                        }
                    }
                } else {
                    Write-Host '    No Java agents found' -ForegroundColor Green
                }
                if ($commandLine -match '-Dfabric\.addMods=' -or $commandLine -match '-Dfml\.coreMods\.load=' -or $commandLine -match '-Dforge\.mods=') {
                    Write-Host '    [!] FABRIC/FORGE INJECTION DETECTED' -ForegroundColor Red
                    $foundInjection = $true
                }
                Write-Host ''
            }
        } catch {
            Write-Host "  Could not access command line for PID $($proc.Id)" -ForegroundColor Gray
            Write-Host ''
        }
    }
    if (-not $foundInjection) {
        Write-Host '  [i] No JVM argument injection detected.' -ForegroundColor Green
        Write-Host ''
    }
}

# ============================================================================
# MODS FOLDER TAMPERING CHECK
# ============================================================================
Write-Host $line1 -ForegroundColor Yellow
Write-Host 'MODS FOLDER TAMPERING CHECK' -ForegroundColor Yellow
Write-Host $line1 -ForegroundColor Yellow
Write-Host ''
$modsFolder = Get-Item $mods
$modsModified = $modsFolder.LastWriteTime
$timeSinceModsChange = (Get-Date) - $modsModified
Write-Host "Mods folder last modified: $modsModified" -ForegroundColor White
Write-Host "Time since change: $($timeSinceModsChange.Hours)h $($timeSinceModsChange.Minutes)m $($timeSinceModsChange.Seconds)s" -ForegroundColor White
if ($timeSinceModsChange.TotalMinutes -lt 15) {
    Write-Host '!!! WARNING: Mods folder modified within last 15 minutes !!!' -ForegroundColor Red
    Write-Host '    This is during your screenshare session.' -ForegroundColor Red
    Write-Host '    Strong indicator of tampering/self-destruct.' -ForegroundColor Red
} else {
    Write-Host 'Mods folder not recently tampered with' -ForegroundColor Green
}
Write-Host ''

# ============================================================================
# CHEAT STRING DETECTION (Binary scan of mods folder)
# ============================================================================
Write-Host $line1 -ForegroundColor Magenta
Write-Host 'CHEAT STRING DETECTION (Binary Scan)' -ForegroundColor Magenta
Write-Host $line1 -ForegroundColor Magenta
Write-Host ''
$cheatStrings = @('Doomsday','prestige','psaclient','198m','Auto Crystal','Anchor Macro','fastplace','Self Destruct','Aimbot')
$jarFiles = Get-ChildItem -Path $mods -Filter '*.jar' -File
if ($jarFiles.Count -eq 0) {
    Write-Host 'No .jar files found in mods folder.' -ForegroundColor Yellow
    Write-Host ''
} else {
    foreach ($jar in $jarFiles) {
        Write-Host "Scanning: $($jar.Name)" -NoNewline
        $found = $false
        try {
            $bytes = [System.IO.File]::ReadAllBytes($jar.FullName)
            $content = [System.Text.Encoding]::ASCII.GetString($bytes)
            foreach ($string in $cheatStrings) {
                if ($content.Contains($string)) {
                    if (-not $found) { Write-Host ''; $found = $true }
                    Write-Host "  [!] FOUND: $string" -ForegroundColor Red
                }
            }
            if (-not $found) { Write-Host ' - Clean' -ForegroundColor Green }
        } catch { Write-Host ' - Error reading file' -ForegroundColor Yellow }
    }
    Write-Host ''
}

# ============================================================================
# MEMORY SCANNER (C# embedded)
# ============================================================================
Write-Host $line1 -ForegroundColor Magenta
Write-Host 'TARGETED MEMORY SCANNER (Mapped+Private)' -ForegroundColor Magenta
Write-Host $line1 -ForegroundColor Magenta
Write-Host ''
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
public class MemoryScanner {
    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")] private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out uint lpNumberOfBytesRead);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_EXECUTE_READ = 0x20;
    public static bool ScanProcess(int pid, string[] needles, Action<string> outputCallback) {
        bool foundAny = false;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) { outputCallback("  [!] Failed to open process (try running as Administrator)"); return false; }
        try {
            IntPtr address = IntPtr.Zero;
            while (true) {
                MEMORY_BASIC_INFORMATION mbi;
                int result = VirtualQueryEx(hProcess, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                if (result == 0) break;
                if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READ) && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_PRIVATE)) {
                    long regionSize = (long)mbi.RegionSize;
                    long offset = 0;
                    const int chunkSize = 1024 * 1024;
                    while (offset < regionSize) {
                        int bytesToRead = (int)Math.Min(chunkSize, regionSize - offset);
                        byte[] buffer = new byte[bytesToRead];
                        uint bytesRead;
                        long baseAddrLong = mbi.BaseAddress.ToInt64();
                        IntPtr readAddress = new IntPtr(baseAddrLong + offset);
                        if (ReadProcessMemory(hProcess, readAddress, buffer, (uint)bytesToRead, out bytesRead) && bytesRead > 0) {
                            string regionText = Encoding.ASCII.GetString(buffer, 0, (int)bytesRead);
                            foreach (string needle in needles) if (regionText.Contains(needle)) { outputCallback(needle); foundAny = true; }
                        }
                        offset += bytesToRead;
                    }
                }
                long nextAddrLong = mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize;
                address = new IntPtr(nextAddrLong);
            }
        } finally { CloseHandle(hProcess); }
        return foundAny;
    }
}
"@ -ErrorAction SilentlyContinue

$cheatPatterns = @{
    'Prestige' = @('prestigeclient.vip','.prestigeclient.vip0','prestige_4.properties','assets/minecraft/optifine/cit/profile/prestige/','prestigeclient.vip0Y0','prestige')
    'Doomsday' = @('Doomsday','DoomsdayClient','DoomsdayClient:::bot),%.R','DoomsdayClient:::u;<r,7NVce;Ga25','DoomsdayClient:::eObOiPdFJR 2','DoomsdayClient:::Wu&XNC]30?3=7')
    'GenericModules' = @('198m')
}
$javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($javaw) {
    Write-Host "  Scanning javaw.exe PID $($javaw.Id) for targeted cheat patterns..." -ForegroundColor White
    $foundInMemory = $false
    $stringToCheat = @{}
    foreach ($cheatName in $cheatPatterns.Keys) { foreach ($s in $cheatPatterns[$cheatName]) { $stringToCheat[$s] = $cheatName } }
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
    } catch { Write-Host "  [!] Memory scanner error: $_" -ForegroundColor Red }
    if (-not $foundInMemory) { Write-Host '  [+] No known cheat strings found in memory' -ForegroundColor Green }
} else { Write-Host '  [!] javaw.exe not running' -ForegroundColor Yellow }
Write-Host ''

# ============================================================================
# DLL INJECTION DETECTION
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
Write-Host 'DLL INJECTION DETECTION' -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
$javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($javaw) {
    Write-Host "  Scanning modules in javaw.exe PID $($javaw.Id) ..." -ForegroundColor White
    $modules = $javaw.Modules | Where-Object { $_.ModuleName -like '*.dll' }
    $foundSuspicious = $false
    $knownGood = @('java.dll','jvm.dll','verify.dll','zip.dll','net.dll','nio.dll')
    foreach ($mod in $modules) {
        if ($knownGood -contains $mod.ModuleName) { continue }
        $sig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction SilentlyContinue
        if (-not $sig -or $sig.Status -ne 'Valid') {
            Write-Host "    [!] Unsigned/Invalid DLL: $($mod.ModuleName)" -ForegroundColor Red
            Write-Host "        Path: $($mod.FileName)" -ForegroundColor Gray
            $foundSuspicious = $true
        }
    }
    if (-not $foundSuspicious) { Write-Host '  [+] No suspicious DLLs found.' -ForegroundColor Green }
} else { Write-Host '  [!] javaw.exe not running.' -ForegroundColor Yellow }
Write-Host ''

# ============================================================================
# NETWORK CONNECTION MONITORING (IP obfuscated)
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
Write-Host 'NETWORK CONNECTIONS' -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
$javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($javaw) {
    $connections = Get-NetTCPConnection -OwningProcess $javaw.Id -ErrorAction SilentlyContinue
    if ($connections) {
        Write-Host "  Active connections from javaw.exe:" -ForegroundColor White
        foreach ($conn in $connections) {
            $remoteAddr = $conn.RemoteAddress
            if ($remoteAddr -match '(\d+\.\d+\.\d+)\.\d+') { $remoteAddr = $matches[1] + '.xxx' }
            elseif ($remoteAddr -match '^([a-fA-F0-9:]+):[a-fA-F0-9:]+$') { $remoteAddr = $matches[1] + ':xxx' }
            Write-Host ("    {0}:{1} -> {2}:{3} [{4}]" -f $conn.LocalAddress, $conn.LocalPort, $remoteAddr, $conn.RemotePort, $conn.State) -ForegroundColor Yellow
        }
    } else { Write-Host '  [+] No active connections.' -ForegroundColor Green }
} else { Write-Host '  [!] javaw.exe not running.' -ForegroundColor Yellow }
Write-Host ''

# ============================================================================
# PREFETCH ANALYSIS (lightweight)
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
Write-Host 'PREFETCH EXECUTION HISTORY' -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
$pfPath = 'C:\Windows\Prefetch'
if (Test-Path $pfPath) {
    $pfFiles = Get-ChildItem $pfPath -Filter '*.pf' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 20
    if ($pfFiles) {
        Write-Host '  Most recent Prefetch files (last 20):' -ForegroundColor White
        foreach ($pf in $pfFiles) {
            $exeName = ($pf.Name -split '-')[0]
            Write-Host "    $exeName  –  Last run: $($pf.LastWriteTime)" -ForegroundColor Yellow
        }
        Write-Host ''
        Write-Host '  (Full analysis of loaded modules requires WinPrefetchView)' -ForegroundColor Gray
    } else { Write-Host '  [!] No Prefetch files found (SysMain service may be disabled).' -ForegroundColor Yellow }
} else { Write-Host '  [!] Prefetch folder not found.' -ForegroundColor Yellow }
Write-Host ''

# ============================================================================
# USN JOURNAL FORENSICS (recent file activity)
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
Write-Host 'USN JOURNAL – RECENT FILE ACTIVITY' -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
$drive = 'C:'
try {
    $journalInfo = fsutil usn queryjournal $drive 2>$null
    if ($journalInfo -match 'Usn Journal ID\s+:\s+0x(\w+)') {
        Write-Host "  Journal ID: 0x$($matches[1])" -ForegroundColor White
        $tempFile = [System.IO.Path]::GetTempFileName()
        fsutil usn readjournal $drive csv > $tempFile 2>$null
        $entries = Import-Csv $tempFile | Where-Object { $_.TimeStamp -and [datetime]$_.TimeStamp -gt (Get-Date).AddHours(-1) }
        Remove-Item $tempFile -Force
        if ($entries) {
            Write-Host "  Entries from the last hour:" -ForegroundColor White
            $entries | Select-Object FileName, Reason, TimeStamp -First 20 | ForEach-Object {
                $color = if ($_.Reason -match 'DELETE') { 'Red' } elseif ($_.Reason -match 'RENAME') { 'Yellow' } else { 'Gray' }
                Write-Host "    $($_.FileName) [$($_.Reason)] at $($_.TimeStamp)" -ForegroundColor $color
            }
        } else { Write-Host '  [+] No recent journal entries.' -ForegroundColor Green }
    } else { Write-Host '  [!] USN Journal not found or inaccessible.' -ForegroundColor Yellow }
} catch { Write-Host "  [!] Error reading USN Journal: $_" -ForegroundColor Red }
Write-Host ''

# ============================================================================
# RECENTDOCS REGISTRY CHECK
# ============================================================================
Write-Host $line1 -ForegroundColor DarkCyan
Write-Host 'RECENTLY OPENED FILES (RecentDocs)' -ForegroundColor DarkCyan
Write-Host $line1 -ForegroundColor DarkCyan
Write-Host ''
$recentPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
if (Test-Path $recentPath) {
    $recentItems = Get-ChildItem $recentPath -ErrorAction SilentlyContinue
    $suspicious = @()
    foreach ($item in $recentItems) {
        $value = (Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue).'(default)'
        if ($value -and $value -match '\.(jar|exe|dll|bat|ps1|py|vbs)$') { $suspicious += $value }
    }
    if ($suspicious) {
        Write-Host '  [!] Suspicious recently opened files:' -ForegroundColor Red
        $suspicious | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    } else { Write-Host '  [+] No suspicious recent files.' -ForegroundColor Green }
} else { Write-Host '  [!] RecentDocs key not found.' -ForegroundColor Gray }
Write-Host ''

# ============================================================================
# EXECUTION EVIDENCE CHECK (PCA)
# ============================================================================
Write-Host $line1 -ForegroundColor DarkCyan
Write-Host 'EXECUTION EVIDENCE CHECK (PCA)' -ForegroundColor DarkCyan
Write-Host $line1 -ForegroundColor DarkCyan
Write-Host ''
$pcaPath = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
if (Test-Path $pcaPath) {
    $pcaEntries = Get-ItemProperty -Path $pcaPath -ErrorAction SilentlyContinue
    $pcaValues = $pcaEntries.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -First 10
    if ($pcaValues) {
        Write-Host '  Recently executed programs (PCA Store):' -ForegroundColor Yellow
        foreach ($entry in $pcaValues) { Write-Host "    $($entry.Name)" -ForegroundColor White }
    } else { Write-Host '  No execution entries found.' -ForegroundColor Gray }
}
Write-Host ''

# ============================================================================
# OBFUSCATION DETECTION
# ============================================================================
Write-Host $line1 -ForegroundColor DarkYellow
Write-Host 'OBFUSCATION DETECTION' -ForegroundColor DarkYellow
Write-Host $line1 -ForegroundColor DarkYellow
Write-Host ''
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
$jarFiles = Get-ChildItem -Path $mods -Filter '*.jar' -File
if ($jarFiles.Count -eq 0) {
    Write-Host 'No .jar files found in mods folder.' -ForegroundColor Yellow
    Write-Host ''
} else {
    foreach ($jar in $jarFiles) {
        $obfuscationScore = 0
        $reasons = @()
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)
            $singleCount = 0; $twoCount = 0; $numberedCount = 0; $totalClasses = 0
            foreach ($entry in $zip.Entries) {
                if ($entry.Name -match '\.class$') {
                    $totalClasses++
                    if ($entry.Name -match '^[a-zA-Z]\.class$') { $singleCount++ }
                    if ($entry.Name -match '^[a-zA-Z]{2}\.class$') { $twoCount++ }
                    if ($entry.Name -match '^\d+\.class$') { $numberedCount++ }
                }
            }
            $zip.Dispose()
            if ($totalClasses -ge 10) {
                if ($numberedCount -gt 5) { $obfuscationScore += 3; $reasons += "$numberedCount numbered classes - PRESTIGE PATTERN" }
                if ($singleCount -gt 5)  { $obfuscationScore += 2; $reasons += "$singleCount single-letter classes" }
                if ($twoCount -gt 20)    { $obfuscationScore += 1; $reasons += "$twoCount two-letter classes" }
                if ($obfuscationScore -ge 3) {
                    Write-Host "$($jar.Name): RED - HEAVILY OBFUSCATED" -ForegroundColor Red
                    foreach ($r in $reasons) { Write-Host "  - $r" -ForegroundColor Red }
                } elseif ($obfuscationScore -ge 1) {
                    Write-Host "$($jar.Name): YELLOW - Possibly obfuscated" -ForegroundColor Yellow
                    foreach ($r in $reasons) { Write-Host "  - $r" -ForegroundColor Yellow }
                }
            }
        } catch { Write-Host "$($jar.Name): Error reading file" -ForegroundColor Gray }
    }
    Write-Host ''
}

# ============================================================================
# DOWNLOAD ORIGIN CHECK (Zone.Identifier)
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
Write-Host 'DOWNLOAD ORIGIN CHECK' -ForegroundColor Cyan
Write-Host $line1 -ForegroundColor Cyan
Write-Host ''
$jarFiles = Get-ChildItem -Path $mods -Filter '*.jar' -File
$foundZone = $false
foreach ($jar in $jarFiles) {
    $zonePath = $jar.FullName + ':Zone.Identifier'
    if (Test-Path $zonePath) { $foundZone = $true; Write-Host "$($jar.Name): Downloaded from internet" -ForegroundColor Yellow }
}
if (-not $foundZone) { Write-Host 'No Zone.Identifier streams found (files were extracted/moved).' -ForegroundColor Gray }
Write-Host ''

# ============================================================================
# UNLOADED MOD DETECTION (manual reminder)
# ============================================================================
Write-Host $line1 -ForegroundColor Red
Write-Host 'UNLOADED MOD DETECTION (Manual Check)' -ForegroundColor Red
Write-Host $line1 -ForegroundColor Red
Write-Host ''
$javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($javaw) {
    Write-Host '!!! MANUAL STEP REQUIRED (if memory scanner missed something) !!!' -ForegroundColor Red
    Write-Host ''
    Write-Host '1. Open System Informer' -ForegroundColor White
    Write-Host "2. Right-click javaw.exe PID $($javaw.Id) - Properties - Memory - Strings" -ForegroundColor White
    Write-Host '3. Set Min length: 5, select Mapped + Private' -ForegroundColor White
    Write-Host '4. Click Strings, then Filter' -ForegroundColor White
    Write-Host ''
    Write-Host "   Filter contains: $mods" -ForegroundColor White
    Write-Host ''
    Write-Host '   If you see .jar paths here that are NOT in your mods folder = SELF DESTRUCT' -ForegroundColor Red
    Write-Host ''
} else { Write-Host 'javaw.exe not running - cannot check for unloaded mods' -ForegroundColor Red; Write-Host '' }

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host $line1 -ForegroundColor Green
Write-Host 'SCAN COMPLETE - LUZING ULTIMATE V3.0' -ForegroundColor Green
Write-Host $line1 -ForegroundColor Green
Write-Host ''
Write-Host '!!! REMINDER: Prestige/Rise/Lambda may be memory-only !!!' -ForegroundColor Yellow
Write-Host '   The automated memory scanner above checks only Mapped+Private regions and specific strings.' -ForegroundColor Yellow
Write-Host '   If it found nothing but you suspect injection, use manual System Informer check.' -ForegroundColor Yellow
Write-Host ''
$exitMsg = 'Press any key to exit...'
Write-Host $exitMsg -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey()
Clear-Host
