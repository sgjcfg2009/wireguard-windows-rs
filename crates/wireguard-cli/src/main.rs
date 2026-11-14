#![windows_subsystem = "windows"]

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.

//! WireGuard for Windows - Command Line Interface & Service Dispatcher.
//!
//! Entry point matching `wireguard.exe` commands:
//! - `/installmanagerservice`: Installs and starts the WireGuard Manager daemon service.
//! - `/uninstallmanagerservice`: Stops and removes the WireGuard Manager daemon service.
//! - `/installtunnelservice <config_path>`: Installs and starts a tunnel service for the given configuration.
//! - `/uninstalltunnelservice <tunnel_name>`: Stops and removes a tunnel service.
//! - `/managerservice`: Internal service entry point for the manager service called by SCM.
//! - `/tunnelservice <config_path>`: Internal service entry point for the tunnel service called by SCM.
//! - `/dumplog [/tail]`: Dumps or follows the ringlogger circular log buffer to standard output.
//! - `/version`: Prints version and operating system information.

use std::env;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::ptr;
use tracing::info;

use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, SW_HIDE, SW_SHOWNORMAL,
};

fn with_wide_null<R>(s: &str, f: impl FnOnce(*const u16) -> R) -> R {
    let mut stack_buf = [0u16; 260];
    let mut len = 0usize;
    let mut overflow = false;
    for unit in s.encode_utf16() {
        if len < 259 {
            stack_buf[len] = unit;
            len += 1;
        } else {
            overflow = true;
            break;
        }
    }
    if !overflow {
        stack_buf[len] = 0;
        return f(stack_buf.as_ptr());
    }
    let vec_buf: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    f(vec_buf.as_ptr())
}

fn show_message_box(title: &str, text: &str, icon: u32) {
    with_wide_null(title, |t_w| {
        with_wide_null(text, |m_w| unsafe {
            MessageBoxW(ptr::null_mut(), m_w, t_w, MB_OK | icon);
        })
    });
}

fn fatal(message: &str) -> ! {
    eprintln!("Error: {}", message);
    wireguard_ui::log_to_file(&format!("FATAL: {}", message));
    show_message_box("WireGuard Error", message, MB_ICONERROR);
    exit(1);
}

fn print_usage() {
    let usage = r#"WireGuard for Windows (100% Rust)

Usage: wireguard.exe [command]

Commands:
    (no arguments)
        Launch the WireGuard Graphical User Interface (GUI).

    /ui
        Launch the WireGuard Graphical User Interface (GUI).

    /installmanagerservice
        Install and start the WireGuard manager service.

    /uninstallmanagerservice
        Stop and remove the WireGuard manager service.

    /installtunnelservice <path\to\config.conf>
        Install and start a dedicated tunnel service for the specified configuration file.

    /uninstalltunnelservice <tunnel_name>
        Stop and remove the tunnel service for the specified tunnel name.

    /managerservice
        Run the manager service (dispatched by Windows Service Control Manager).

    /tunnelservice <path\to\config.conf>
        Run the tunnel service (dispatched by Windows Service Control Manager).

    /dumplog [/tail]
        Dump circular log buffer or continuously follow output.

    /install [/silent]
        Install WireGuard into C:\Program Files\WireGuard, create shortcuts, and register uninstaller.

    /uninstall [/silent]
        Stop services, remove shortcuts, and uninstall WireGuard.

    /version
        Display version and system architecture information.
"#;
    println!("{}", usage);
    show_message_box("WireGuard Command Line Options", usage, MB_ICONINFORMATION);
    exit(0);
}

fn ensure_elevation() {
    ensure_elevation_with_show(SW_SHOWNORMAL as i32);
}

fn ensure_elevation_with_show(show_cmd: i32) {
    if !wireguard_elevate::is_current_process_elevated() {
        if let Ok(exe) = env::current_exe() {
            let exe_str = exe.to_string_lossy();
            // Ensure the executable itself carries High Mandatory Integrity Level so Windows
            // never downgrades the spawned process token to Low Integrity (0x1000) if located
            // inside a Low-Mandatory-Label folder.
            let _ = std::process::Command::new("icacls.exe")
                .args([exe_str.as_ref(), "/setintegritylevel", "High", "/C"])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .status();

            let args: Vec<String> = env::args().skip(1).collect();
            let joined_args = args
                .iter()
                .map(|a| {
                    if a.contains(' ') {
                        format!("\"{}\"", a)
                    } else {
                        a.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            match wireguard_elevate::shell_execute_runas(
                &exe.to_string_lossy(),
                &joined_args,
                None,
                show_cmd,
            ) {
                Ok(_) => exit(0),
                Err(e) => {
                    fatal(&format!(
                        "Administrator privileges are required for this command. Please run as Administrator.\nError: {}",
                        e
                    ));
                }
            }
        }
    }
}

fn launch_ui(tray_only: bool) {
    if wireguard_ui::ensure_single_instance(!tray_only) {
        wireguard_ui::log_to_file(if tray_only {
            "Existing elevated WireGuard UI instance already running; keeping tray state."
        } else {
            "raise_ui() returned true (existing elevated window raised). Exiting."
        });
        return;
    }

    if !wireguard_elevate::is_current_process_elevated() {
        wireguard_ui::log_to_file(
            "Current process is not elevated. Requesting elevation via UAC...",
        );
        ensure_elevation_with_show(if tray_only {
            SW_HIDE as i32
        } else {
            SW_SHOWNORMAL as i32
        });
    }

    let result = if tray_only {
        wireguard_ui::log_to_file("Running elevated UI in tray-only mode (hidden)...");
        wireguard_ui::run_ui_tray()
    } else {
        wireguard_ui::log_to_file("Running elevated UI...");
        wireguard_ui::run_ui()
    };

    if let Err(e) = result {
        wireguard_ui::log_to_file(&format!("UI failed with error: {}", e));
        fatal(&format!("WireGuard UI error: {}", e));
    }
    wireguard_ui::log_to_file("UI returned successfully.");
}

fn main() {
    wireguard_ui::log_to_file("================ STARTUP ================");
    wireguard_ui::log_to_file(&format!(
        "Process ID: {}, Args: {:?}",
        std::process::id(),
        std::env::args().collect::<Vec<_>>()
    ));

    std::panic::set_hook(Box::new(|info| {
        let msg = format!("WireGuard Fatal Panic:\n{}", info);
        eprintln!("{}", msg);
        wireguard_ui::log_to_file(&msg);
        show_message_box("WireGuard Fatal Error", &msg, MB_ICONERROR);
    }));

    // If run from an existing console (cmd/powershell), attach to its standard output
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        wireguard_ui::log_to_file("Invoked with no arguments.");
        launch_ui(false);
        return;
    }

    let command = args[1].to_lowercase();

    match command.as_str() {
        "/ui" => {
            wireguard_ui::log_to_file("Invoked with /ui.");
            launch_ui(false);
        }

        "/tray" | "/startup" | "/minimized" => {
            wireguard_ui::log_to_file("Invoked with /tray (logon startup).");
            launch_ui(true);
        }

        "/help" | "-h" | "--help" | "/?" => {
            print_usage();
        }

        "/version" | "-v" | "--version" => {
            println!("WireGuard for Windows v{} (Rust implementation)", env!("CARGO_PKG_VERSION"));
            let os_info = wireguard_version::os_version();
            println!("OS: Windows {}.{}.{} (Build {})", os_info.major, os_info.minor, os_info.build, os_info.build);
        }

        "/installmanagerservice" => {
            ensure_elevation();
            info!("Installing WireGuard Manager service...");
            let exe_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("wireguard.exe"));
            let binary_path = format!("\"{}\" /managerservice", exe_path.display());

            match wireguard_service::ScmHandle::open_sc_manager(None, None, SC_MANAGER_ALL_ACCESS) {
                Ok(scm) => {
                    match scm.create_service(
                        "WireGuardManager",
                        "WireGuard Manager",
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        &binary_path,
                        None,
                        None,
                        None,
                        None,
                    ) {
                        Ok(svc) => {
                            println!("WireGuard Manager service installed successfully.");
                            let _ = svc.start_service(&[]);
                        }
                        Err(e) => fatal(&format!("Failed to install service: {}", e)),
                    }
                }
                Err(e) => fatal(&format!("Failed to connect to Service Control Manager: {}", e)),
            }
        }

        "/uninstallmanagerservice" => {
            ensure_elevation();
            info!("Uninstalling WireGuard Manager service...");
            match wireguard_service::ScmHandle::open_sc_manager(None, None, SC_MANAGER_ALL_ACCESS) {
                Ok(scm) => {
                    match scm.open_service("WireGuardManager", SERVICE_ALL_ACCESS) {
                        Ok(svc) => {
                            let _ = svc.stop_service();
                            if let Err(e) = svc.delete_service() {
                                fatal(&format!("Failed to delete service: {}", e));
                            } else {
                                println!("WireGuard Manager service uninstalled successfully.");
                            }
                        }
                        Err(e) => fatal(&format!("Service not found or unable to open: {}", e)),
                    }
                }
                Err(e) => fatal(&format!("Failed to connect to SCM: {}", e)),
            }
        }

        "/installtunnelservice" => {
            if args.len() < 3 {
                fatal("Missing configuration file path. Usage: /installtunnelservice <path\\to\\config.conf>");
            }
            ensure_elevation();
            let conf_path = Path::new(&args[2]);
            let tunnel_name = wireguard_conf::name_from_path(conf_path)
                .unwrap_or_else(|e| fatal(&format!("Invalid config file: {}", e)));

            let service_name = wireguard_conf::service_name_of_tunnel(&tunnel_name)
                .unwrap_or_else(|e| fatal(&format!("Invalid tunnel name: {}", e)));

            let exe_path = env::current_exe().unwrap_or_else(|_| PathBuf::from("wireguard.exe"));
            let binary_path = format!("\"{}\" /tunnelservice \"{}\"", exe_path.display(), conf_path.display());

            match wireguard_service::ScmHandle::open_sc_manager(None, None, SC_MANAGER_ALL_ACCESS) {
                Ok(scm) => {
                    let display_name = format!("WireGuard Tunnel: {}", tunnel_name);
                    let svc_res = match scm.open_service(&service_name, SERVICE_ALL_ACCESS) {
                        Ok(existing) => {
                            if existing
                                .update_config(
                                    SERVICE_AUTO_START,
                                    Some(&binary_path),
                                    Some(&display_name),
                                )
                                .is_ok()
                            {
                                Ok(existing)
                            } else {
                                drop(existing);
                                scm.create_service(
                                    &service_name,
                                    &display_name,
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS,
                                    SERVICE_AUTO_START,
                                    SERVICE_ERROR_NORMAL,
                                    &binary_path,
                                    None,
                                    Some(&["Nsi", "TcpIp"]),
                                    None,
                                    None,
                                )
                            }
                        }
                        Err(_) => scm.create_service(
                            &service_name,
                            &display_name,
                            SERVICE_ALL_ACCESS,
                            SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_AUTO_START,
                            SERVICE_ERROR_NORMAL,
                            &binary_path,
                            None,
                            Some(&["Nsi", "TcpIp"]),
                            None,
                            None,
                        ),
                    };
                    match svc_res {
                        Ok(svc) => {
                            unsafe {
                                let mut sid_info =
                                    windows_sys::Win32::System::Services::SERVICE_SID_INFO {
                                        dwServiceSidType:
                                            windows_sys::Win32::System::Services::SERVICE_SID_TYPE_UNRESTRICTED,
                                    };
                                windows_sys::Win32::System::Services::ChangeServiceConfig2W(
                                    svc.as_raw(),
                                    windows_sys::Win32::System::Services::SERVICE_CONFIG_SERVICE_SID_INFO,
                                    &mut sid_info as *mut _ as *const core::ffi::c_void,
                                );
                            }
                            println!("WireGuard tunnel service '{}' installed.", service_name);
                            let _ = svc.start_service(&[]);
                        }
                        Err(e) => fatal(&format!("Failed to install tunnel service: {}", e)),
                    }
                }
                Err(e) => fatal(&format!("Failed to connect to SCM: {}", e)),
            }
        }

        "/uninstalltunnelservice" => {
            if args.len() < 3 {
                fatal("Missing tunnel name. Usage: /uninstalltunnelservice <tunnel_name>");
            }
            ensure_elevation();
            let tunnel_name = &args[2];
            let service_name = wireguard_conf::service_name_of_tunnel(tunnel_name)
                .unwrap_or_else(|e| fatal(&format!("Invalid tunnel name: {}", e)));

            match wireguard_service::ScmHandle::open_sc_manager(None, None, SC_MANAGER_ALL_ACCESS) {
                Ok(scm) => {
                    match scm.open_service(&service_name, SERVICE_ALL_ACCESS) {
                        Ok(svc) => {
                            let _ = svc.stop_service();
                            if let Err(e) = svc.delete_service() {
                                fatal(&format!("Failed to delete tunnel service: {}", e));
                            } else {
                                println!("WireGuard tunnel service '{}' uninstalled.", service_name);
                            }
                        }
                        Err(e) => fatal(&format!("Tunnel service not found: {}", e)),
                    }
                }
                Err(e) => fatal(&format!("Failed to connect to SCM: {}", e)),
            }
        }

        "/managerservice" => {
            // SCM dispatcher for the Manager Service
            if let Err(e) = wireguard_manager::run_manager_service() {
                fatal(&format!("WireGuard Manager service failed: {}", e));
            }
        }

        "/tunnelservice" => {
            if args.len() < 3 {
                fatal("Missing configuration path. Usage: /tunnelservice <path>");
            }
            let conf_path = Path::new(&args[2]);
            if let Err(e) = wireguard_tunnel::run(conf_path) {
                let log_bin = Path::new(r"C:\Program Files\WireGuard\Data\log.bin");
                let _ = wireguard_ringlog::init_global_logger(log_bin, "TUN");
                let _ = wireguard_ringlog::log(&format!(
                    "ERROR: WireGuard Tunnel service failed for '{}': {}",
                    conf_path.display(),
                    e
                ));
                exit(1);
            }
        }

        "/dumplog" => {
            let tail = args.len() > 2 && args[2].eq_ignore_ascii_case("/tail");
            let log_bin = Path::new(r"C:\Program Files\WireGuard\Data\log.bin");
            if let Ok(logger) = wireguard_ringlog::RingLogger::open(log_bin, "DMP") {
                let mut stdout = std::io::stdout().lock();
                if tail {
                    let _ = wireguard_ringlog::stream_mem_to(
                        logger.log_mem(),
                        &mut stdout,
                        std::time::Duration::from_millis(250),
                        None,
                    );
                } else {
                    let _ = wireguard_ringlog::write_mem_to(logger.log_mem(), &mut stdout);
                }
            }
        }

        "/install" | "/silentinstall" => {
            let silent = command == "/silentinstall"
                || (args.len() > 2 && args[2].eq_ignore_ascii_case("/silent"));
            ensure_elevation();
            run_install(silent);
        }

        "/uninstall" | "/silentuninstall" => {
            let silent = command == "/silentuninstall"
                || (args.len() > 2 && args[2].eq_ignore_ascii_case("/silent"));
            ensure_elevation();
            run_uninstall(silent);
        }

        _ => {
            print_usage();
        }
    }
}

fn run_install(silent: bool) {
    let install_dir = Path::new(r"C:\Program Files\WireGuard");
    let data_dir = install_dir.join(r"Data\Configurations");
    let _ = std::fs::create_dir_all(&data_dir);

    let current_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("wireguard.exe"));
    let src_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    let target_exe = install_dir.join("wireguard.exe");

    // Stop existing UI process if running from target_exe so we can overwrite it
    if current_exe != target_exe {
        let _ = std::process::Command::new("taskkill.exe")
            .args(["/F", "/IM", "wireguard.exe", "/FI", &format!("PID ne {}", std::process::id())])
            .creation_flags(0x08000000)
            .status();
        std::thread::sleep(std::time::Duration::from_millis(200));

        if let Err(e) = std::fs::copy(&current_exe, &target_exe) {
            fatal(&format!("Failed to copy wireguard.exe to {}: {}", target_exe.display(), e));
        }
    }

    for extra in ["wireguard.dll", "wireguard.h"] {
        let src_extra = src_dir.join(extra);
        let dst_extra = install_dir.join(extra);
        if src_extra.exists() && src_extra != dst_extra {
            let _ = std::fs::copy(&src_extra, &dst_extra);
        }
    }

    let _ = std::process::Command::new("icacls.exe")
        .args([r"C:\Program Files\WireGuard", "/setintegritylevel", "High", "/T", "/C"])
        .creation_flags(0x08000000)
        .status();

    // Create Start Menu & Desktop shortcuts and Uninstall Registry key
    let ps_script = r#"
$WshShell = New-Object -ComObject WScript.Shell
$Target = 'C:\Program Files\WireGuard\wireguard.exe'
$StartMenu = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\WireGuard.lnk'
$Desktop = [Environment]::GetFolderPath('CommonDesktopDirectory') + '\WireGuard.lnk'
foreach ($lnk in @($StartMenu, $Desktop)) {
    $s = $WshShell.CreateShortcut($lnk)
    $s.TargetPath = $Target
    $s.WorkingDirectory = 'C:\Program Files\WireGuard'
    $s.Description = 'WireGuard VPN Client'
    $s.Save()
}
$RegPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\WireGuard'
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name 'DisplayName' -Value 'WireGuard'
Set-ItemProperty -Path $RegPath -Name 'DisplayVersion' -Value '0.5.3'
Set-ItemProperty -Path $RegPath -Name 'Publisher' -Value 'WireGuard Rust Contributors'
Set-ItemProperty -Path $RegPath -Name 'DisplayIcon' -Value $Target
Set-ItemProperty -Path $RegPath -Name 'InstallLocation' -Value 'C:\Program Files\WireGuard'
Set-ItemProperty -Path $RegPath -Name 'UninstallString' -Value "`"$Target`" /uninstall"
Set-ItemProperty -Path $RegPath -Name 'NoModify' -Value 1 -Type DWord
Set-ItemProperty -Path $RegPath -Name 'NoRepair' -Value 1 -Type DWord
"#;
    let _ = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script])
        .creation_flags(0x08000000)
        .status();

    if !silent {
        show_message_box(
            "WireGuard Setup",
            "WireGuard has been installed successfully into C:\\Program Files\\WireGuard.\n\nShortcuts have been created on your Desktop and Start Menu.",
            MB_ICONINFORMATION,
        );
        let _ = std::process::Command::new(&target_exe).spawn();
    }
}

fn run_uninstall(silent: bool) {
    // 1. Stop and remove manager service and any active WireGuardTunnel$* services
    if let Ok(scm) = wireguard_service::ScmHandle::open_sc_manager(None, None, SC_MANAGER_ALL_ACCESS) {
        if let Ok(svc) = scm.open_service("WireGuardManager", SERVICE_ALL_ACCESS) {
            let _ = svc.stop_service();
            let _ = svc.delete_service();
        }
        let conf_dir = Path::new(r"C:\Program Files\WireGuard\Data\Configurations");
        if let Ok(names) = wireguard_conf::store::list_config_names(conf_dir) {
            for name in names {
                if let Ok(svc_name) = wireguard_conf::service_name_of_tunnel(&name) {
                    if let Ok(svc) = scm.open_service(&svc_name, SERVICE_ALL_ACCESS) {
                        let _ = svc.stop_service();
                        let _ = svc.delete_service();
                    }
                }
            }
        }
    }

    // 2. Stop any running wireguard.exe UI instances other than this uninstaller
    let _ = std::process::Command::new("taskkill.exe")
        .args(["/F", "/IM", "wireguard.exe", "/FI", &format!("PID ne {}", std::process::id())])
        .creation_flags(0x08000000)
        .status();

    // 3. Remove Start Menu & Desktop shortcuts, any remaining WireGuardTunnel$* services, scheduled tasks, and registry keys
    let _ = wireguard_manager::autostart::set_windows_logon_autostart(false);
    let ps_script = r#"
Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $_.Name | Out-Null
}
schtasks.exe /delete /tn "WireGuard" /f 2>&1 | Out-Null
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WireGuard' -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\Software\WireGuard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\WireGuard.lnk' -Force -ErrorAction SilentlyContinue
$Desktop = [Environment]::GetFolderPath('CommonDesktopDirectory') + '\WireGuard.lnk'
Remove-Item -Path $Desktop -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\WireGuard' -Recurse -Force -ErrorAction SilentlyContinue
"#;
    let _ = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script])
        .creation_flags(0x08000000)
        .status();

    let install_dir = Path::new(r"C:\Program Files\WireGuard");
    let _ = std::fs::remove_file(install_dir.join("wireguard.dll"));
    let _ = std::fs::remove_file(install_dir.join("wireguard.h"));
    let _ = std::fs::remove_dir_all(install_dir.join("Data"));

    if !silent {
        show_message_box(
            "WireGuard Uninstall",
            "WireGuard and all associated files have been completely uninstalled from your computer.",
            MB_ICONINFORMATION,
        );
    }

    // 4. Schedule complete deletion of C:\Program Files\WireGuard after this process exits
    let _ = std::process::Command::new("cmd.exe")
        .current_dir(r"C:\Windows\Temp")
        .args([
            "/C",
            r#"ping 127.0.0.1 -n 2 >nul & del /f /q "C:\Program Files\WireGuard\wireguard.exe" >nul 2>&1 & rmdir /s /q "C:\Program Files\WireGuard" >nul 2>&1"#,
        ])
        .creation_flags(0x08000000)
        .spawn();
}
