# ============================================================================
# AUTO-ELEVATE TO ADMINISTRATOR
# ============================================================================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`""
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

# Set console background to black
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# ============================================================================
# HEADER
# ============================================================================
$line1 = '=================================================='
$line2 = ' luzing SS analyzer v2.4 '
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
Write-Host "Luzing's analyzer v2.4 - Efficient" -ForegroundColor Cyan
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
# GLOBAL PATTERN DEFINITIONS (used by multiple functions)
# ============================================================================
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
    'CrystalPVPModules' = @(
        '.psaclient',
        'Auto Crystal',
        'Anchor Macro',
        'fastplace',
        'autocrystal',
        'legit totem',
        'CrystalAura',
        'AnchorAura',
        'LegitRetotem',
        'Auto Dtap',
        'Auto Hit Crystal',
        'Self Destruct',
        'AutoInventoryTotem',
        'Auto Shield Disabler',
        'Auto Mace',
        'Aimbot'
    )
}

# ============================================================================
# MAIN SCAN FUNCTION (can be re-run)
# ============================================================================
function Invoke-MainScan {
    param($mods)

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
    Write-Host $line1 -ForegroundColor Cyan
    $header1 = 'JVM ARGUMENTS INJECTION SCANNER'
    Write-Host $header1 -ForegroundColor Yellow
    Write-Host $line1 -ForegroundColor Cyan
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
    Write-Host $line1 -ForegroundColor Cyan
    $header2 = 'MODS FOLDER TAMPERING CHECK'
    Write-Host $header2 -ForegroundColor Yellow
    Write-Host $line1 -ForegroundColor Cyan
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
    Write-Host $line1 -ForegroundColor Cyan
    $header3 = 'CHEAT STRING DETECTION (Binary Scan)'
    Write-Host $header3 -ForegroundColor Magenta
    Write-Host $line1 -ForegroundColor Cyan
    Write-Host ''

    $cheatStrings = @(
        'Doomsday',
        'prestige',
        'psaclient',
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
    Write-Host $line1 -ForegroundColor Cyan
    $headerMem = 'TARGETED MEMORY SCANNER (Mapped+Private)'
    Write-Host $headerMem -ForegroundColor Magenta
    Write-Host $line1 -ForegroundColor Cyan
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
        Write-Host '  [i] javaw.exe not running' -ForegroundColor Yellow
    }
    Write-Host ''

    # ============================================================================
    # SUSPICIOUS PROCESS SCANNER (with system folder check)
    # ============================================================================
    Write-Host $line1 -ForegroundColor Cyan
    $headerSusp = 'SUSPICIOUS PROCESS SCANNER'
    Write-Host $headerSusp -ForegroundColor Yellow
    Write-Host $line1 -ForegroundColor Cyan
    Write-Host ''

    $systemPaths = @(
        'C:\Windows\*',
        'C:\Program Files\*',
        'C:\Program Files (x86)\*'
    )

    $allProcesses = Get-Process | Where-Object { $_.SessionId -ne 0 } | Sort-Object ProcessName
    $foundSuspicious = $false

    foreach ($proc in $allProcesses) {
        try {
            $path = $proc.Path
            if (-not $path) { continue }
            
            # Check digital signature
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            $isSigned = ($sig -and $sig.Status -eq 'Valid')
            
            # Determine if path is in a system directory
            $inSystem = $false
            foreach ($sys in $systemPaths) {
                if ($path -like $sys) {
                    $inSystem = $true
                    break
                }
            }
            
            # If unsigned and in system folder → extremely suspicious
            if (-not $isSigned -and $inSystem) {
                Write-Host "    [!!!] EXTREMELY SUSPICIOUS: Unsigned process in system folder - $($proc.ProcessName)" -ForegroundColor Red
                Write-Host "        Path: $path" -ForegroundColor Gray
                Write-Host "        PID: $($proc.Id)" -ForegroundColor Gray
                $foundSuspicious = $true
            }
            # If unsigned and outside system folders → likely cheat
            elseif (-not $isSigned -and -not $inSystem) {
                Write-Host "    [!] Unsigned process running from non-system location: $($proc.ProcessName)" -ForegroundColor Yellow
                Write-Host "        Path: $path" -ForegroundColor Gray
                Write-Host "        PID: $($proc.Id)" -ForegroundColor Gray
                $foundSuspicious = $true
            }
        } catch {
            # Skip inaccessible processes
        }
    }

    if (-not $foundSuspicious) {
        Write-Host '  [+] No unsigned processes found.' -ForegroundColor Green
    }
    Write-Host ''

    # ============================================================================
    # DLL INJECTION DETECTION (with expanded whitelist)
    # ============================================================================
    Write-Host $line1 -ForegroundColor Cyan
    $headerDll = 'DLL INJECTION DETECTION'
    Write-Host $headerDll -ForegroundColor Yellow
    Write-Host $line1 -ForegroundColor Cyan
    Write-Host ''

    $javaw = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($javaw) {
        Write-Host "  Scanning modules in javaw.exe PID $($javaw.Id) ..." -ForegroundColor White
        $modules = $javaw.Modules | Where-Object { $_.ModuleName -like '*.dll' }
        $foundSuspicious = $false
        
        # Known good DLLs (by exact filename)
        $knownGoodFilenames = @(
            'java.dll', 'jvm.dll', 'verify.dll', 'zip.dll', 'net.dll', 'nio.dll',
            'awt.dll', 'fontmanager.dll', 'freetype.dll', 'jawt.dll', 'jsvml.dll',
            'lcms.dll', 'mlib_image.dll', 'msvcr100.dll', 'msvcp100.dll', 'prefs.dll',
            'splashscreen.dll', 'sunec.dll', 'sunmscapi.dll', 'unpack.dll',
            'management.dll', 'management_ext.dll', 'jdwp.dll', 'dt_socket.dll',
            'hprof.dll', 'instrument.dll', 'j2pkcs11.dll', 'jaas.dll',
            'kcms.dll', 'mlib_image_v.dll', 'rmi.dll', 't2k.dll',
            # LWJGL and game native libraries
            'lwjgl.dll', 'jemalloc.dll', 'glfw.dll', 'lwjgl_opengl.dll', 'lwjgl_stb.dll', 'OpenAL.dll',
            'libopus4j.dll', 'librnnoise4j.dll', 'libspeex4j.dll', 'liblame4j.dll'
        )
        
        # Known safe path patterns (if a DLL is in these folders, consider it safe regardless of name)
        $safePathPatterns = @(
            '\\ModrinthApp\\meta\\natives\\',
            '\\AppData\\Local\\Temp\\libopus4j-',
            '\\AppData\\Local\\Temp\\librnnoise4j-',
            '\\AppData\\Local\\Temp\\libspeex4j-',
            '\\AppData\\Local\\Temp\\liblame4j-',
            '\\AppData\\Local\\Temp\\jna[0-9]+'
        )
        
        foreach ($mod in $modules) {
            $fileName = $mod.ModuleName
            $filePath = $mod.FileName
            
            # Skip by exact filename
            if ($knownGoodFilenames -contains $fileName) { continue }
            
            # Skip by path pattern
            $isSafePath = $false
            foreach ($pattern in $safePathPatterns) {
                if ($filePath -match $pattern) {
                    $isSafePath = $true
                    break
                }
            }
            if ($isSafePath) { continue }
            
            # Check digital signature
            $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
            if (-not $sig -or $sig.Status -ne 'Valid') {
                Write-Host "    [!] Unsigned/Invalid DLL: $fileName" -ForegroundColor Red
                Write-Host "        Path: $filePath" -ForegroundColor Gray
                $foundSuspicious = $true
            }
        }
        if (-not $foundSuspicious) {
            Write-Host '  [+] No suspicious DLLs found.' -ForegroundColor Green
        }
    } else {
        Write-Host '  [i] javaw.exe not running.' -ForegroundColor Yellow
    }
    Write-Host ''

    # ============================================================================
    # OBFUSCATION DETECTION
    # ============================================================================
    Write-Host $line1 -ForegroundColor Cyan
    $header4 = 'OBFUSCATION DETECTION'
    Write-Host $header4 -ForegroundColor DarkYellow
    Write-Host $line1 -ForegroundColor Cyan
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
    Write-Host $header5 -ForegroundColor Yellow
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
    Write-Host $line1 -ForegroundColor Cyan
    $header6 = 'UNLOADED MOD DETECTION (Manual Check)'
    Write-Host $header6 -ForegroundColor Red
    Write-Host $line1 -ForegroundColor Cyan
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
    # RECENTDOCS REGISTRY CHECK
    # ============================================================================
    Write-Host $line1 -ForegroundColor Cyan
    $headerRecent = 'RECENTLY OPENED FILES (RecentDocs)'
    Write-Host $headerRecent -ForegroundColor DarkCyan
    Write-Host $line1 -ForegroundColor Cyan
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
    # USB DEVICE HISTORY CHECK
    # ============================================================================
    Write-Host $line1 -ForegroundColor Cyan
    $headerUSB = 'USB DEVICE HISTORY'
    Write-Host $headerUSB -ForegroundColor Yellow
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
                if (-not $friendlyName) { continue }

                $lastConnected = $instance.LastWriteTime
                if ($lastConnected -isnot [DateTime]) {
                    try { $lastConnected = [DateTime]::Parse($lastConnected) } catch { $lastConnected = $now }
                }
                $firstConnected = $instance.CreationTime
                if ($firstConnected -isnot [DateTime]) {
                    try { $firstConnected = [DateTime]::Parse($firstConnected) } catch { $firstConnected = $now }
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
                if ($hoursAgo -lt 24) { $recentDevices += $deviceInfo }
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
    Write-Host $line1 -ForegroundColor Cyan
    $summaryHeader = 'SCAN COMPLETE - LUZING ULTIMATE V2.4'
    Write-Host $summaryHeader -ForegroundColor Green
    Write-Host $line1 -ForegroundColor Cyan
    Write-Host ''

    $reminder1 = '!!! REMINDER: Prestige/Rise/Lambda may be memory-only !!!'
    $reminder2 = '   The automated memory scanner above checks only Mapped+Private regions and specific strings.'
    $reminder3 = '   If it found nothing but you suspect injection, use manual System Informer check.'
    Write-Host $reminder1 -ForegroundColor Yellow
    Write-Host $reminder2 -ForegroundColor Yellow
    Write-Host $reminder3 -ForegroundColor Yellow
    Write-Host ''
}

# ============================================================================
# INTERACTIVE COMMANDS (BAM, PCA, HashCheck, StringScan, Prefetch, Rescan)
# ============================================================================
function Show-BAM {
    Write-Host "`n--- BAM Forensics (Recently Executed Programs) ---" -ForegroundColor Cyan
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\"
    if (Test-Path $bamPath) {
        $userSIDs = Get-ChildItem $bamPath -ErrorAction SilentlyContinue
        if ($userSIDs) {
            foreach ($sid in $userSIDs) {
                $props = Get-ItemProperty -Path $sid.PSPath -ErrorAction SilentlyContinue
                $found = $false
                Write-Host "  User SID: $($sid.PSChildName)" -ForegroundColor Yellow
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -notlike "PS*") {
                        $binaryData = $prop.Value
                        if ($binaryData -is [byte[]]) {
                            # Try Unicode decoding first
                            $text = [System.Text.Encoding]::Unicode.GetString($binaryData)
                            $strings = $text -split '\0' | Where-Object { $_ -match '^[a-zA-Z]:\\.+\.(exe|dll|jar|bat|ps1)$' }
                            foreach ($str in $strings) {
                                Write-Host "    $str" -ForegroundColor White
                                $found = $true
                            }
                            # If none found, try ASCII decoding
                            if (-not $found) {
                                $textAscii = [System.Text.Encoding]::ASCII.GetString($binaryData)
                                $stringsAscii = $textAscii -split '\0' | Where-Object { $_ -match '^[a-zA-Z]:\\.+\.(exe|dll|jar|bat|ps1)$' }
                                foreach ($str in $stringsAscii) {
                                    Write-Host "    $str" -ForegroundColor White
                                    $found = $true
                                }
                            }
                        }
                    }
                }
                if (-not $found) {
                    Write-Host "    No executable entries found." -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "  No BAM user settings found." -ForegroundColor Gray
        }
    } else {
        Write-Host "  BAM registry path not found." -ForegroundColor Gray
    }
    Write-Host ""
}

function Show-PCA {
    Write-Host "`n--- PCA Store (Recently Executed Programs) ---" -ForegroundColor Cyan
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
    Write-Host ""
}

function Show-HashCheck {
    Write-Host "`n--- HASH DATABASE SCAN ---" -ForegroundColor Cyan
    Write-Host "Scanning all fixed drives for executables and comparing against known cheat hashes..." -ForegroundColor White

    # Known cheat hashes – extend this list as you discover more
    $cheatHashes = @{
        "A515D5965EAA6D7788F933B8683FA9182DEBF95E5A81B7F3B41F7E751CD412A9" = "198macros v1.4.0"
        "E88DC150D4E79EFD2186355036B9548AC29A8063D04C7A83457E1B0A9C398D29" = "Prestige Injector"
        # Add other known hashes here, e.g.:
        # "B626E6A7FBB7D8889F044C9794FA0293ECF0A6F6B92C8F4C52F8E862CD523BA0" = "Prestige Client v3"
        # "C737F7B8GCC8E9990F155D0805GB1304FDG1B7G7C03D9G5D63G9F973D634CB1" = "Doomsday Client"
    }

    # Get all fixed drives (C:, D:, etc.)
    $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady }
    $fileExtensions = @('*.exe', '*.jar', '*.dll')
    $filesFound = @()
    $matchesFound = $false

    foreach ($drive in $drives) {
        Write-Host "  Scanning $($drive.Name) ..." -ForegroundColor Gray
        try {
            foreach ($ext in $fileExtensions) {
                $files = Get-ChildItem -Path $drive.RootDirectory.FullName -Filter $ext -Recurse -ErrorAction SilentlyContinue -File |
                         Where-Object { $_.Length -gt 1MB -and $_.Length -lt 20MB } # focus on plausible cheat sizes
                $filesFound += $files
            }
        } catch {
            Write-Host "    [!] Error scanning drive $($drive.Name): $_" -ForegroundColor Yellow
        }
    }

    # Remove duplicates (same file might be found in multiple scans)
    $filesFound = $filesFound | Sort-Object FullName -Unique

    if ($filesFound.Count -eq 0) {
        Write-Host "  No executable files found." -ForegroundColor Gray
    } else {
        Write-Host "  Checking $($filesFound.Count) files..." -ForegroundColor White
        foreach ($file in $filesFound) {
            try {
                $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                if ($cheatHashes.ContainsKey($hash)) {
                    Write-Host "    [!!!] CONFIRMED CHEAT: $($cheatHashes[$hash])" -ForegroundColor Red
                    Write-Host "          Path: $($file.FullName)" -ForegroundColor Gray
                    Write-Host "          Size: $([math]::Round($file.Length/1MB,2)) MB" -ForegroundColor Gray
                    Write-Host "          Modified: $($file.LastWriteTime)" -ForegroundColor Gray
                    $matchesFound = $true
                }
            } catch {
                # hash computation failed – skip
            }
        }
    }

    if (-not $matchesFound) {
        Write-Host "  [+] No known cheat hashes matched." -ForegroundColor Green
    }
    Write-Host ""
}

function Show-StringScan {
    Write-Host "`n--- STRING PATTERN SCAN (Pseudo-YARA) ---" -ForegroundColor Cyan
    Write-Host "Scanning user folders for files (3.5MB - 18.75MB) containing cheat strings..." -ForegroundColor White

    # Collect all unique cheat strings from our patterns
    $allCheatStrings = $cheatPatterns.Values | ForEach-Object { $_ } | Sort-Object -Unique

    # Target folders – cheats are almost always in these locations
    $targetFolders = @(
        [System.Environment]::GetFolderPath('UserProfile') + "\Downloads",
        [System.Environment]::GetFolderPath('Desktop'),
        [System.Environment]::GetFolderPath('UserProfile') + "\AppData\Roaming",
        [System.Environment]::GetFolderPath('UserProfile') + "\AppData\Local\Temp",
        [System.Environment]::GetFolderPath('UserProfile') + "\Documents"
    )

    # Size range for cheats (in bytes)
    $minSize = 3.5 * 1MB  # 3.5 MB
    $maxSize = 18.75 * 1MB # 18.75 MB

    $fileExtensions = @('*.exe', '*.jar', '*.dll')
    $totalMatches = 0
    $filesScanned = 0

    foreach ($folder in $targetFolders) {
        if (-not (Test-Path $folder)) { continue }
        Write-Host "  Scanning $folder ..." -ForegroundColor Gray
        foreach ($ext in $fileExtensions) {
            try {
                $files = Get-ChildItem -Path $folder -Filter $ext -Recurse -ErrorAction SilentlyContinue -File |
                         Where-Object { $_.Length -ge $minSize -and $_.Length -le $maxSize }
                foreach ($file in $files) {
                    $filesScanned++
                    # Show progress every 20 files
                    if ($filesScanned % 20 -eq 0) {
                        Write-Host "    Scanned $filesScanned files..." -NoNewline -ForegroundColor Gray
                        Write-Host " `r" -NoNewline
                    }
                    try {
                        # Read first 200KB – cheat strings are usually near the start
                        $buffer = [byte[]]::new(200 * 1024)
                        $stream = [System.IO.File]::OpenRead($file.FullName)
                        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                        $stream.Close()
                        $content = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                        
                        foreach ($string in $allCheatStrings) {
                            if ($content.Contains($string)) {
                                Write-Host "`n    [!!!] STRING MATCH: $string" -ForegroundColor Red
                                Write-Host "          Path: $($file.FullName)" -ForegroundColor Gray
                                Write-Host "          Size: $([math]::Round($file.Length/1MB,2)) MB" -ForegroundColor Gray
                                Write-Host "          Modified: $($file.LastWriteTime)" -ForegroundColor Gray
                                $totalMatches++
                                break # Stop checking this file once a match is found
                            }
                        }
                    } catch {
                        # Skip files that can't be read
                    }
                }
            } catch {
                # Skip inaccessible paths
            }
        }
    }

    Write-Host "" # New line after progress
    if ($totalMatches -eq 0) {
        Write-Host "  [+] No cheat strings found in scanned files." -ForegroundColor Green
    } else {
        Write-Host "  [!] Scan complete. $totalMatches potential cheat(s) detected via string patterns." -ForegroundColor Yellow
    }
    Write-Host ""
}

function Show-Prefetch {
    Write-Host "`n--- PREFETCH EXECUTION HISTORY ---" -ForegroundColor Cyan
    $pfPath = 'C:\Windows\Prefetch'
    if (Test-Path $pfPath) {
        $pfFiles = Get-ChildItem $pfPath -Filter '*.pf' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20
        if ($pfFiles) {
            Write-Host "  Most recent Prefetch files (last 20):" -ForegroundColor White
            foreach ($pf in $pfFiles) {
                # Extract executable name (part before the first '-')
                $exeName = ($pf.Name -split '-')[0]
                $lastRun = $pf.LastWriteTime
                $timeSince = (Get-Date) - $lastRun
                $timeStr = if ($timeSince.TotalHours -lt 1) { "less than an hour ago" }
                           elseif ($timeSince.TotalHours -lt 24) { "$([math]::Round($timeSince.TotalHours,1)) hours ago" }
                           else { "$([math]::Round($timeSince.TotalDays,1)) days ago" }
                Write-Host "    $exeName - Last run: $lastRun ($timeStr)" -ForegroundColor Yellow
            }
            Write-Host ''
            Write-Host '  (Note: Prefetch files are created when programs run; they persist after deletion.)' -ForegroundColor Gray
        } else {
            Write-Host '  No Prefetch files found (SysMain service may be disabled).' -ForegroundColor Yellow
        }
    } else {
        Write-Host '  Prefetch folder not found.' -ForegroundColor Gray
    }
    Write-Host ''
}

# ============================================================================
# RUN INITIAL SCAN
# ============================================================================
Invoke-MainScan -mods $mods

# ============================================================================
# INTERACTIVE LOOP
# ============================================================================
Write-Host $line1 -ForegroundColor Cyan
Write-Host "Enter a command (type 'help' for options):" -ForegroundColor Yellow
Write-Host $line1 -ForegroundColor Cyan
do {
    $response = Read-Host "> "
    switch ($response.ToLower()) {
        'close' {
            Write-Host "Exiting..." -ForegroundColor Gray
            break
        }
        'rescan' {
            Clear-Host
            Invoke-MainScan -mods $mods
        }
        'showranexe' {
            Show-BAM
        }
        'pcasearch' {
            Show-PCA
        }
        'hashcheck' {
            Show-HashCheck
        }
        'stringscan' {
            Show-StringScan
        }
        'prefetch' {
            Show-Prefetch
        }
        'help' {
            Write-Host "Available commands:" -ForegroundColor Green
            Write-Host "  rescan      - Re-run all main scans (clears previous output)"
            Write-Host "  ShowRanExe  - Display recently executed programs from BAM registry"
            Write-Host "  PCASearch   - Display recently executed programs from PCA Store"
            Write-Host "  HashCheck   - Scan all drives and compare file hashes against known cheat database"
            Write-Host "  StringScan  - Scan user folders for files containing known cheat strings (3.5-18.75MB)"
            Write-Host "  prefetch    - Show recent Prefetch execution history"
            Write-Host "  close       - Exit the script"
            Write-Host "  help        - Show this help"
        }
        default {
            Write-Host "Unknown command. Type 'help' for options." -ForegroundColor Red
        }
    }
} while ($response -ne 'close')

Clear-Host
