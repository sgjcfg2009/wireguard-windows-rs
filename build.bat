@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ===============================================================================
echo                WIREGUARD FOR WINDOWS - 100%% RUST BUILD SYSTEM
echo ===============================================================================
echo.

set "LOCAL_TOOLS_DIR=%~dp0tools"
set "LOCAL_CARGO_HOME=%LOCAL_TOOLS_DIR%\cargo"
set "LOCAL_RUSTUP_HOME=%LOCAL_TOOLS_DIR%\rustup"
set "LOCAL_TMP_DIR=%LOCAL_TOOLS_DIR%\tmp"
set "LOCAL_TARGET_DIR=%~dp0target"
set "WGNT_DIR=%LOCAL_TOOLS_DIR%\wireguard-nt"
set "WGNT_DLL=%WGNT_DIR%\bin\amd64\wireguard.dll"
set "WGNT_ZIP=%LOCAL_TOOLS_DIR%\wireguard-nt-1.1.zip"

if not exist "%LOCAL_TOOLS_DIR%" mkdir "%LOCAL_TOOLS_DIR%"
if not exist "%LOCAL_TMP_DIR%" mkdir "%LOCAL_TMP_DIR%"
if not exist "%LOCAL_TARGET_DIR%" mkdir "%LOCAL_TARGET_DIR%"
icacls.exe "%LOCAL_TOOLS_DIR%" /setintegritylevel Medium >nul 2>&1
icacls.exe "%LOCAL_TMP_DIR%" /setintegritylevel Medium >nul 2>&1
icacls.exe "%LOCAL_TARGET_DIR%" /setintegritylevel Medium >nul 2>&1
set "TEMP=%LOCAL_TMP_DIR%"
set "TMP=%LOCAL_TMP_DIR%"

REM Multi-threaded download & build configuration
set "CPU_CORES=%NUMBER_OF_PROCESSORS%"
if "%CPU_CORES%"=="" set "CPU_CORES=4"
set "CARGO_BUILD_JOBS=%CPU_CORES%"
set "CARGO_HTTP_MULTIPLEXING=true"
set "CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse"
set "CARGO_NET_RETRY=3"
set "RUSTUP_CONCURRENT_DOWNLOADS=8"

if exist "%LOCAL_CARGO_HOME%\bin\cargo.exe" (
    set "CARGO_HOME=%LOCAL_CARGO_HOME%"
    set "RUSTUP_HOME=%LOCAL_RUSTUP_HOME%"
    set "PATH=%LOCAL_CARGO_HOME%\bin;%PATH%"
) else if exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
    set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)

where cargo.exe >nul 2>&1
if errorlevel 1 (
    call :install_rust
    if errorlevel 1 (
        set "BUILD_EXIT_CODE=1"
        goto :done
    )
    set "CARGO_HOME=%LOCAL_CARGO_HOME%"
    set "RUSTUP_HOME=%LOCAL_RUSTUP_HOME%"
    set "PATH=%LOCAL_CARGO_HOME%\bin;%PATH%"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
set "BUILD_EXIT_CODE=%ERRORLEVEL%"

:done
echo.
echo ===============================================================================
if "%BUILD_EXIT_CODE%"=="0" (
    echo [OK] Build hoan tat thanh cong!
) else (
    echo [X] Build ket thuc voi ma loi: %BUILD_EXIT_CODE%
)
echo ===============================================================================
echo.
echo Nhan mot phim bat ky de dong cua so...
pause >nul
exit /b %BUILD_EXIT_CODE%

:install_rust
echo [!] Chua co Rust build tools. Dang tai da luong va cai dat vao ".\tools\"...
if not exist "%LOCAL_TOOLS_DIR%" mkdir "%LOCAL_TOOLS_DIR%"
set "CARGO_HOME=%LOCAL_CARGO_HOME%"
set "RUSTUP_HOME=%LOCAL_RUSTUP_HOME%"

if not exist "%LOCAL_TOOLS_DIR%\rustup-init.exe" (
    echo [*] Dang tai rustup-init.exe...
    set "NEED_WGNT=0"
    if not exist "%WGNT_DLL%" if not exist "%WGNT_ZIP%" set "NEED_WGNT=1"
    call :download_deps
)

if not exist "%LOCAL_TOOLS_DIR%\rustup-init.exe" (
    echo [X] Khong the tai rustup-init.exe! Vui long kiem tra ket noi mang.
    exit /b 1
)

echo [*] Dang cai dat Rust toolchain ^(stable-x86_64-pc-windows-msvc^) vao "%LOCAL_TOOLS_DIR%"...
"%LOCAL_TOOLS_DIR%\rustup-init.exe" -y --no-modify-path --default-toolchain stable --profile minimal --default-host x86_64-pc-windows-msvc
if errorlevel 1 (
    echo [X] Cai dat Rust toolchain that bai!
    exit /b 1
)

icacls.exe "%LOCAL_CARGO_HOME%" /setintegritylevel Medium /T /C >nul 2>&1
icacls.exe "%LOCAL_RUSTUP_HOME%" /setintegritylevel Medium /T /C >nul 2>&1
echo [OK] Da cai dat xong Rust build tools tai "%LOCAL_CARGO_HOME%\bin".
echo.
exit /b 0

:download_deps
where curl.exe >nul 2>&1
if not errorlevel 1 (
    if "%NEED_WGNT%"=="1" (
        curl.exe --parallel --parallel-immediate --parallel-max 8 -fSL --retry 3 --retry-delay 1 -o "%LOCAL_TOOLS_DIR%\rustup-init.exe" "https://win.rustup.rs/x86_64" -o "%WGNT_ZIP%" "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip"
    ) else (
        curl.exe -fSL --retry 3 --retry-delay 1 -o "%LOCAL_TOOLS_DIR%\rustup-init.exe" "https://win.rustup.rs/x86_64"
    )
    if exist "%LOCAL_TOOLS_DIR%\rustup-init.exe" exit /b 0
    echo [!] curl.exe that bai, chuyen sang PowerShell de tai...
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile '%LOCAL_TOOLS_DIR%\rustup-init.exe'"
exit /b 0
