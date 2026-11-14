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

if not exist "%LOCAL_TOOLS_DIR%" mkdir "%LOCAL_TOOLS_DIR%"
if not exist "%LOCAL_TMP_DIR%" mkdir "%LOCAL_TMP_DIR%"
if not exist "%LOCAL_TARGET_DIR%" mkdir "%LOCAL_TARGET_DIR%"
icacls.exe "%LOCAL_TOOLS_DIR%" /setintegritylevel Medium >nul 2>&1
icacls.exe "%LOCAL_TMP_DIR%" /setintegritylevel Medium >nul 2>&1
icacls.exe "%LOCAL_TARGET_DIR%" /setintegritylevel Medium >nul 2>&1
set "TEMP=%LOCAL_TMP_DIR%"
set "TMP=%LOCAL_TMP_DIR%"

if exist "%LOCAL_CARGO_HOME%\bin\cargo.exe" (
    set "CARGO_HOME=%LOCAL_CARGO_HOME%"
    set "RUSTUP_HOME=%LOCAL_RUSTUP_HOME%"
    set "PATH=%LOCAL_CARGO_HOME%\bin;%PATH%"
) else if exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
    set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
)

where cargo.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Chua co Rust build tools. Dang tai va cai dat ngay ke ben trong ".\tools\"...
    if not exist "%LOCAL_TOOLS_DIR%" mkdir "%LOCAL_TOOLS_DIR%"
    set "CARGO_HOME=%LOCAL_CARGO_HOME%"
    set "RUSTUP_HOME=%LOCAL_RUSTUP_HOME%"

    if not exist "%LOCAL_TOOLS_DIR%\rustup-init.exe" (
        echo [*] Dang tai rustup-init.exe...
        where curl.exe >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            curl.exe -fSL -o "%LOCAL_TOOLS_DIR%\rustup-init.exe" "https://win.rustup.rs/x86_64"
        ) else (
            powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile '%LOCAL_TOOLS_DIR%\rustup-init.exe'"
        )
    )

    if not exist "%LOCAL_TOOLS_DIR%\rustup-init.exe" (
        echo [X] Khong the tai rustup-init.exe! Vui long kiem tra ket noi mang.
        exit /b 1
    )

    echo [*] Dang cai dat Rust toolchain ^(stable-x86_64-pc-windows-msvc^) vao "%LOCAL_TOOLS_DIR%"...
    "%LOCAL_TOOLS_DIR%\rustup-init.exe" -y --no-modify-path --default-toolchain stable --profile minimal --default-host x86_64-pc-windows-msvc
    if %ERRORLEVEL% neq 0 (
        echo [X] Cai dat Rust toolchain that bai!
        exit /b %ERRORLEVEL%
    )

    icacls.exe "%LOCAL_CARGO_HOME%" /setintegritylevel Medium /T /C >nul 2>&1
    icacls.exe "%LOCAL_RUSTUP_HOME%" /setintegritylevel Medium /T /C >nul 2>&1
    set "PATH=%LOCAL_CARGO_HOME%\bin;%PATH%"
    echo [OK] Da cai dat xong Rust build tools tai "%LOCAL_CARGO_HOME%\bin".
    echo.
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
set "BUILD_EXIT_CODE=%ERRORLEVEL%"

echo.
echo ===============================================================================
if %BUILD_EXIT_CODE% equ 0 (
    echo [OK] Build hoan tat thanh cong!
) else (
    echo [X] Build ket thuc voi ma loi: %BUILD_EXIT_CODE%
)
echo ===============================================================================
echo.
echo Nhan mot phim bat ky de dong cua so...
pause >nul
exit /b %BUILD_EXIT_CODE%
