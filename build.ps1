# WireGuard Windows (100% Rust) - Build Script
$ErrorActionPreference = "Stop"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "                WIREGUARD FOR WINDOWS - 100% RUST BUILD SYSTEM" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = $PSScriptRoot
Set-Location $projectRoot

$distDir = Join-Path $projectRoot "dist"
$toolsDir = Join-Path $projectRoot "tools"
$localTmpDir = Join-Path $toolsDir "tmp"
$targetDir = Join-Path $projectRoot "target"

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
}
if (-not (Test-Path $localTmpDir)) {
    New-Item -ItemType Directory -Path $localTmpDir -Force | Out-Null
}
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}
& icacls.exe $toolsDir /setintegritylevel Medium | Out-Null
& icacls.exe $localTmpDir /setintegritylevel Medium /T /C | Out-Null
& icacls.exe $targetDir /setintegritylevel Medium /T /C | Out-Null
$env:TEMP = $localTmpDir
$env:TMP = $localTmpDir

# 1. Check and configure Rust Toolchain
Write-Host "[*] STEP 1: Checking Rust toolchain..." -ForegroundColor Yellow

$localCargoHome = Join-Path $toolsDir "cargo"
$localRustupHome = Join-Path $toolsDir "rustup"
$localCargoBin = Join-Path $localCargoHome "bin"
$userCargoBin = Join-Path $env:USERPROFILE ".cargo\bin"

if (Test-Path (Join-Path $localCargoBin "cargo.exe")) {
    $env:CARGO_HOME = $localCargoHome
    $env:RUSTUP_HOME = $localRustupHome
    if ($env:PATH -notlike "*$localCargoBin*") {
        $env:PATH = "$localCargoBin;$env:PATH"
    }
} elseif (Test-Path (Join-Path $userCargoBin "cargo.exe")) {
    if ($env:PATH -notlike "*$userCargoBin*") {
        $env:PATH = "$userCargoBin;$env:PATH"
    }
}

$cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue

if (-not $cargoCmd) {
    Write-Host "[!] Rust not found in PATH. Installing portable toolchain into .\tools\..." -ForegroundColor Yellow
    if (-not (Test-Path $toolsDir)) {
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    }
    $env:CARGO_HOME = $localCargoHome
    $env:RUSTUP_HOME = $localRustupHome
    $rustupExe = Join-Path $toolsDir "rustup-init.exe"
    if (-not (Test-Path $rustupExe)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe
    }
    
    Write-Host "[*] Installing Rust toolchain (stable-x86_64-pc-windows-msvc) into $toolsDir..." -ForegroundColor Yellow
    & $rustupExe -y --no-modify-path --default-toolchain stable --profile minimal --default-host x86_64-pc-windows-msvc
    
    $env:PATH = "$localCargoBin;$env:PATH"
}

$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"

$cargoVer = (& cargo --version 2>$null)
$rustcVer = (& rustc --version 2>$null)
Write-Host "[OK] Active Rust toolchain: $cargoVer ($rustcVer)" -ForegroundColor Green
$ErrorActionPreference = $oldEap
Write-Host ""

# 2. Check and configure MSVC Linker
Write-Host "[*] STEP 2: Checking MSVC C++ Linker..." -ForegroundColor Yellow

$linkCmd = Get-Command link -ErrorAction SilentlyContinue
if (-not $linkCmd) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsInstallPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsInstallPath) {
            $vcvars = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $vcvars) {
                Write-Host "[*] Activating MSVC Build Tools environment (x64)..." -ForegroundColor Yellow
                $envLines = cmd.exe /c "call `"$vcvars`" >nul && set"
                foreach ($line in $envLines) {
                    if ($line -match "^(.*?)=(.*)$") {
                        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                    }
                }
                $env:TEMP = $localTmpDir
                $env:TMP = $localTmpDir
            }
        }
    }
}

# 3. Ensure WireGuardNT WHQL driver DLL is available for embedding and setup multi-threaded build
$wgntDir = Join-Path $toolsDir "wireguard-nt"
$wgntDllPath = Join-Path $wgntDir "bin\amd64\wireguard.dll"
if (-not (Test-Path $wgntDllPath)) {
    Write-Host "[*] Downloading official WireGuardNT 1.1 WHQL kernel driver package..." -ForegroundColor Yellow
    if (-not (Test-Path $wgntDir)) {
        New-Item -ItemType Directory -Path $wgntDir -Force | Out-Null
    }
    $wgntZip = Join-Path $toolsDir "wireguard-nt-1.1.zip"
    if (-not (Test-Path $wgntZip)) {
        curl.exe -sSL -o $wgntZip "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip"
    }
    tar.exe -xf $wgntZip -C $wgntDir
    if (-not (Test-Path $wgntDllPath)) {
        $altDll = Get-ChildItem -Path $wgntDir -Filter "wireguard.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*amd64*" } | Select-Object -First 1
        if ($altDll) { $wgntDllPath = $altDll.FullName }
    }
    Write-Host "[OK] Extracted WireGuardNT 1.1 WHQL driver" -ForegroundColor Green
}
if (Test-Path $wgntDllPath) {
    Copy-Item $wgntDllPath -Destination (Join-Path $distDir "wireguard.dll") -Force
}

$cpuCores = [System.Environment]::ProcessorCount
if (-not $cpuCores -or $cpuCores -lt 1) { $cpuCores = 4 }
Write-Host "[*] STEP 3: Multi-threading configured for $cpuCores CPU cores" -ForegroundColor Yellow

$env:CARGO_BUILD_JOBS = "$cpuCores"

Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "                STARTING COMPILATION (CARGO RELEASE)..." -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

# 3.5 Precompile Win32 resources into target\resources.res
$rcExe = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe"
if (-not (Test-Path $rcExe)) {
    $found = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\bin" -Filter "rc.exe" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*x64*" } | Select-Object -First 1
    if ($found) { $rcExe = $found.FullName }
}
if ($rcExe -and (Test-Path $rcExe)) {
    $targetDir = Join-Path $projectRoot "target"
    if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
    
    $rcContent = @"
#pragma code_page(65001)
1 ICON "wireguard.ico"
7 ICON "wireguard.ico"
1 24 "manifest.xml"
wireguard.dll RCDATA "dist\\wireguard.dll"

1 VERSIONINFO
FILEVERSION     0,5,3,0
PRODUCTVERSION  0,5,3,0
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          0x40004L
FILETYPE        0x1L
FILESUBTYPE     0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "WireGuard LLC"
            VALUE "FileDescription", "WireGuard: Fast, Modern, Secure VPN Tunnel"
            VALUE "FileVersion", "0.5.3.0"
            VALUE "InternalName", "wireguard"
            VALUE "OriginalFilename", "wireguard.exe"
            VALUE "ProductName", "WireGuard"
            VALUE "ProductVersion", "0.5.3.0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"@
    $tempRc = Join-Path $targetDir "resources.rc"
    Set-Content -Path $tempRc -Value $rcContent -Encoding UTF8
    $resFile = Join-Path $targetDir "resources.res"
    Push-Location $projectRoot
    & $rcExe /nologo /fo $resFile $tempRc | Out-Null
    Pop-Location
    Write-Host "[OK] Compiled Win32 resources (Icon, Manifest, Driver) -> target\resources.res" -ForegroundColor Green
}

# Run cargo build
& cargo build --release --workspace --jobs $cpuCores
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[X] BUILD FAILED! Check the error messages above." -ForegroundColor Red
    exit $LASTEXITCODE
}

# 4. Copy build artifacts to dist folder
Write-Host ""
Write-Host "[*] STEP 4: Collecting build artifacts into: $distDir" -ForegroundColor Yellow

$exePath = Join-Path $projectRoot "target\release\wireguard.exe"
if (Test-Path $exePath) {
    $targetExe = Join-Path $distDir "wireguard.exe"
    Copy-Item $exePath -Destination $distDir -Force

    # Ensure Common-Controls 6.0 & Per-Monitor DPI manifest is embedded in dist\wireguard.exe
    $mtExe = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\mt.exe"
    $manifestXml = Join-Path $projectRoot "manifest.xml"
    if ((Test-Path $mtExe) -and (Test-Path $manifestXml)) {
        & $mtExe -nologo -manifest $manifestXml "-outputresource:${targetExe};#1" | Out-Null
    }

    Write-Host "[OK] Copied: $targetExe (with embedded WireGuard Icon & Manifest)" -ForegroundColor Green

    # Ensure High Mandatory Integrity Level on dist\wireguard.exe so Explorer never downgrades it to Low Integrity
    & icacls.exe $distDir /setintegritylevel High /T /C | Out-Null
    & icacls.exe $targetExe /setintegritylevel High /C | Out-Null
}

$dllPath = Join-Path $projectRoot "tools\wireguard-nt\bin\amd64\wireguard.dll"
if (-not (Test-Path $dllPath)) {
    $dllPath = Join-Path $projectRoot "target\release\wireguard_dll.dll"
}
if (Test-Path $dllPath) {
    Copy-Item $dllPath -Destination (Join-Path $distDir "wireguard.dll") -Force
    Write-Host "[OK] Copied: $(Join-Path $distDir 'wireguard.dll') (WHQL WireGuardNT Driver DLL)" -ForegroundColor Green
}
$embedDllPath = Join-Path $projectRoot "target\release\wireguard_dll.dll"
if (Test-Path $embedDllPath) {
    Copy-Item $embedDllPath -Destination (Join-Path $distDir "tunnel.dll") -Force
    Write-Host "[OK] Copied: $(Join-Path $distDir 'tunnel.dll') (Embeddable Tunnel Service DLL)" -ForegroundColor Green
}

$headerPath = Join-Path $projectRoot "crates\wireguard-dll\wireguard.h"
if (Test-Path $headerPath) {
    Copy-Item $headerPath -Destination $distDir -Force
    Write-Host "[OK] Copied: $(Join-Path $distDir 'wireguard.h')" -ForegroundColor Green
}

# 5. Build Self-Contained Standalone Installer (dist\wireguard-installer.exe)
Write-Host ""
Write-Host "[*] STEP 5: Building standalone installer (dist\wireguard-installer.exe)..." -ForegroundColor Yellow

$cscPath = Join-Path ([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) "csc.exe"
$installerExe = Join-Path $distDir "wireguard-installer.exe"
$distWgExe = Join-Path $distDir "wireguard.exe"
$distWgDll = Join-Path $distDir "wireguard.dll"
$distWgH   = Join-Path $distDir "wireguard.h"

if ((Test-Path $cscPath) -and (Test-Path $distWgExe) -and (Test-Path $distWgDll)) {
    $tempCs = Join-Path $env:TEMP "WireGuardInstallerStub.cs"
    $tempManifest = Join-Path $env:TEMP "WireGuardInstaller.manifest"

    $manifestXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"@
    Set-Content -Path $tempManifest -Value $manifestXml -Encoding UTF8

    $csCode = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("WireGuard Windows Installer")]
[assembly: AssemblyProduct("WireGuard")]
[assembly: AssemblyVersion("0.5.3.0")]

class Program {
    static void ExtractResource(string resName, string outPath) {
        using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName)) {
            if (s == null) return;
            using (FileStream fs = new FileStream(outPath, FileMode.Create, FileAccess.Write)) {
                s.CopyTo(fs);
            }
        }
    }

    [STAThread]
    static int Main(string[] args) {
        bool silent = args.Length > 0 && (args[0].Equals("/silent", StringComparison.OrdinalIgnoreCase) || args[0].Equals("/S", StringComparison.OrdinalIgnoreCase));
        try {
            string installDir = @"C:\Program Files\WireGuard";
            string dataDir = Path.Combine(installDir, @"Data\Configurations");
            Directory.CreateDirectory(dataDir);

            // Stop running UI if any before overwriting
            try {
                Process pKill = Process.Start(new ProcessStartInfo("taskkill.exe", "/F /IM wireguard.exe") { CreateNoWindow = true, UseShellExecute = false });
                if (pKill != null) pKill.WaitForExit(3000);
            } catch {}

            string exeOut = Path.Combine(installDir, "wireguard.exe");
            string dllOut = Path.Combine(installDir, "wireguard.dll");
            string hOut   = Path.Combine(installDir, "wireguard.h");

            ExtractResource("wireguard.exe", exeOut);
            ExtractResource("wireguard.dll", dllOut);
            ExtractResource("wireguard.h",   hOut);

            ProcessStartInfo psi = new ProcessStartInfo(exeOut, silent ? "/silentinstall" : "/install") {
                WorkingDirectory = installDir,
                UseShellExecute = false
            };
            Process p = Process.Start(psi);
            if (p != null) p.WaitForExit();
            return 0;
        } catch (Exception ex) {
            if (!silent) {
                MessageBox.Show("WireGuard installation failed:\n" + ex.Message, "WireGuard Setup Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return 1;
        }
    }
}
"@
    Set-Content -Path $tempCs -Value $csCode -Encoding UTF8

    $icoFile = Join-Path $projectRoot "wireguard.ico"
    $win32IconArg = if (Test-Path $icoFile) { "/win32icon:$icoFile" } else { "" }

    & $cscPath /nologo /target:winexe /optimize+ "/out:$installerExe" "/win32manifest:$tempManifest" $win32IconArg `
        "/resource:$distWgExe,wireguard.exe" `
        "/resource:$distWgDll,wireguard.dll" `
        "/resource:$distWgH,wireguard.h" `
        $tempCs | Out-Null

    Remove-Item $tempCs -Force -ErrorAction SilentlyContinue
    Remove-Item $tempManifest -Force -ErrorAction SilentlyContinue

    if (Test-Path $installerExe) {
        & icacls.exe $installerExe /setintegritylevel High /C | Out-Null
        Write-Host "[OK] Built standalone installer: $installerExe" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "        WIREGUARD WINDOWS RUST BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "        Output Folder: $distDir" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host ""
