// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Tunnel configuration Add/Edit dialog for WireGuard Windows.
//!
//! Faithful native Win32 reimplementation in 100% Rust of `ui/editdialog.go`.
//! Allows creating a new tunnel or editing an existing tunnel configuration:
//! - Name field with validation (must be valid filename, no spaces or reserved names).
//! - Public key field (automatically derived from the private key in real-time).
//! - Multiline configuration editor with monospace font.
//! - "Block untunneled traffic (kill-switch)" checkbox toggle.
//! - Save button: parses config, validates, saves to disk or returns config, exits with IDOK.
//! - Cancel button: discards changes, exits with IDCANCEL.

use std::ptr;
use std::sync::Once;

use windows_sys::Win32::Foundation::{
    FALSE, HWND, LPARAM, LRESULT, RECT, TRUE, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, CreateSolidBrush, DeleteObject, GetStockObject, GetSysColor,
    SetBkMode, SetTextColor, CLIP_DEFAULT_PRECIS, COLOR_BTNFACE,
    COLOR_WINDOWTEXT, DEFAULT_CHARSET, DEFAULT_PITCH, DEFAULT_QUALITY, FF_DONTCARE,
    FW_BOLD, FW_NORMAL, HBRUSH, HDC, HFONT, HGDIOBJ, NULL_BRUSH, OUT_DEFAULT_PRECIS,
    TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, EM_SETSEL,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, SetFocus, VK_RETURN, VK_TAB,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetClientRect, GetMessageW, GetSystemMetrics, GetWindowLongPtrW,
    GetWindowRect, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW, IsWindow,
    LoadCursorW, MessageBoxW, MoveWindow, RegisterClassExW, SendMessageW,
    SetForegroundWindow, SetWindowLongPtrW, SetWindowPos, SetWindowTextW,
    TranslateMessage, BM_GETCHECK, BM_SETCHECK, BN_CLICKED, BS_AUTOCHECKBOX,
    BS_DEFPUSHBUTTON, BS_PUSHBUTTON, EN_CHANGE, ES_AUTOHSCROLL, ES_AUTOVSCROLL,
    ES_MULTILINE, ES_READONLY, ES_WANTRETURN, GWLP_USERDATA, IDCANCEL, IDC_ARROW, IDOK,
    MB_ICONERROR, MB_ICONWARNING, MB_OK, MINMAXINFO, MSG, SM_CXSCREEN, SM_CYSCREEN,
    SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, WM_CLOSE, WM_COMMAND,
    WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DESTROY, WM_GETMINMAXINFO, WM_KEYDOWN,
    WM_SETFONT, WM_SIZE, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN,
    WS_EX_DLGMODALFRAME, WS_EX_WINDOWEDGE, WS_HSCROLL, WS_MAXIMIZEBOX,
    WS_MINIMIZEBOX, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_THICKFRAME, WS_VISIBLE,
    WS_VSCROLL,
};

use wireguard_conf::Config;
use wireguard_types::Key;

use crate::win32_util::{encode_wide_null_into, with_wide_null};

const EDIT_DIALOG_CLASS_NAME: &str = "WireGuardEditDialog";

static REGISTER_DIALOG_ONCE: Once = Once::new();

const IDC_NAME_EDIT: u16 = 101;
const IDC_PUBKEY_EDIT: u16 = 102;
const IDC_CONFIG_EDIT: u16 = 103;
const IDC_KILL_SWITCH_CB: u16 = 104;
const IDC_SAVE_BTN: u16 = IDOK as u16; // 1
const IDC_CANCEL_BTN: u16 = IDCANCEL as u16; // 2

/// Reads `hwnd` text into `out` while reusing both `wide_buf` and `out` buffers.
fn get_window_text_into(hwnd: HWND, wide_buf: &mut Vec<u16>, out: &mut String) {
    out.clear();
    if hwnd.is_null() {
        return;
    }
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return;
        }
        let needed = (len + 1) as usize;
        if wide_buf.len() < needed {
            wide_buf.resize(needed, 0);
        }
        let copied = GetWindowTextW(hwnd, wide_buf.as_mut_ptr(), needed as i32);
        if copied > 0 {
            out.reserve(copied as usize);
            for ch in std::char::decode_utf16(wide_buf[..copied as usize].iter().copied()) {
                out.push(ch.unwrap_or(char::REPLACEMENT_CHARACTER));
            }
        }
    }
}

fn set_window_text_with_buf(hwnd: HWND, text: &str, wide_buf: &mut Vec<u16>) {
    if hwnd.is_null() {
        return;
    }
    encode_wide_null_into(text, wide_buf);
    unsafe {
        SetWindowTextW(hwnd, wide_buf.as_ptr());
    }
}

fn show_dialog_message(hwnd: HWND, msg: &str, title: &str, flags: u32) {
    with_wide_null(msg, |msg_ptr| {
        with_wide_null(title, |title_ptr| unsafe {
            MessageBoxW(hwnd, msg_ptr, title_ptr, flags);
        });
    });
}

/// Normalizes `\n` and `\r\n` line endings to `\r\n` in a single pass.
fn normalize_newlines_to_crlf(input: &str) -> String {
    let bytes = input.as_bytes();
    let extra_cr = bytes
        .iter()
        .enumerate()
        .filter(|&(i, &b)| b == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
        .count();
    if extra_cr == 0 {
        return input.to_owned();
    }

    let mut out = String::with_capacity(input.len() + extra_cr);
    let mut last = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
            out.push_str(&input[last..i]);
            out.push_str("\r\n");
            last = i + 1;
        }
    }
    out.push_str(&input[last..]);
    out
}

/// Extracts the private key value slice from the `[Interface]` section of a WireGuard INI config.
pub fn extract_private_key(text: &str) -> Option<&str> {
    let mut in_interface = false;
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.eq_ignore_ascii_case("[interface]") {
            in_interface = true;
            continue;
        } else if code.starts_with('[') && code.ends_with(']') {
            in_interface = false;
            continue;
        }

        if in_interface {
            if let Some((k, v)) = code.split_once('=') {
                if k.trim().eq_ignore_ascii_case("privatekey") {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

/// Evaluates whether the configuration is currently blocking untunneled traffic:
/// - Returns `Some(true)` if peer AllowedIPs contains `0.0.0.0/0` or `::/0`.
/// - Returns `Some(false)` if peer AllowedIPs contains (`0.0.0.0/1` and `128.0.0.0/1`) or (`::/1` and `8000::/1`).
/// - Returns `None` if unable to evaluate (e.g. not exactly 1 peer, or other ranges).
pub fn evaluate_kill_switch_state(config_text: &str) -> Option<bool> {
    let mut in_peer = false;
    let mut peer_count = 0;
    let mut seen_00v4 = false;
    let mut seen_00v6 = false;
    let mut seen_01v4 = false;
    let mut seen_1281v4 = false;
    let mut seen_01v6 = false;
    let mut seen_80001v6 = false;
    let mut table_off = false;

    for line in config_text.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.eq_ignore_ascii_case("[interface]") {
            in_peer = false;
            continue;
        } else if code.eq_ignore_ascii_case("[peer]") {
            in_peer = true;
            peer_count += 1;
            continue;
        } else if code.starts_with('[') && code.ends_with(']') {
            in_peer = false;
            continue;
        }

        if !in_peer {
            if let Some((k, v)) = code.split_once('=') {
                if k.trim().eq_ignore_ascii_case("table") && v.trim().eq_ignore_ascii_case("off") {
                    table_off = true;
                }
            }
        } else if let Some((k, v)) = code.split_once('=') {
            if k.trim().eq_ignore_ascii_case("allowedips") {
                for item in v.split(',') {
                    let ip = item.trim();
                    match ip {
                        "0.0.0.0/0" => seen_00v4 = true,
                        "::/0" => seen_00v6 = true,
                        "0.0.0.0/1" => seen_01v4 = true,
                        "128.0.0.0/1" => seen_1281v4 = true,
                        "::/1" => seen_01v6 = true,
                        "8000::/1" => seen_80001v6 = true,
                        _ => {}
                    }
                }
            }
        }
    }

    if table_off || peer_count != 1 {
        return None;
    }

    if seen_00v4 || seen_00v6 {
        Some(true)
    } else if (seen_01v4 && seen_1281v4) || (seen_01v6 && seen_80001v6) {
        Some(false)
    } else {
        None
    }
}

/// Toggles the kill switch in the configuration text:
/// - If `enable` is true: converts split default routes (`0.0.0.0/1, 128.0.0.0/1` and `::/1, 8000::/1`) into `0.0.0.0/0` and `::/0`.
/// - If `enable` is false: converts `0.0.0.0/0` and `::/0` into split default routes (`0.0.0.0/1, 128.0.0.0/1` and `::/1, 8000::/1`).
pub fn toggle_kill_switch(config_text: &str, enable: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut in_peer = false;

    for line in config_text.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.eq_ignore_ascii_case("[peer]") {
            in_peer = true;
            lines.push(line.to_string());
            continue;
        } else if code.starts_with('[') && code.ends_with(']') {
            in_peer = false;
            lines.push(line.to_string());
            continue;
        }

        if in_peer && code.len() >= 10 && code[..10].eq_ignore_ascii_case("allowedips") {
            if let Some((k, v)) = line.split_once('=') {
                let ips: Vec<&str> = v
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                let mut new_ips: Vec<String> = Vec::new();

                if enable {
                    let has_v4_half = ips.iter().any(|&s| s == "0.0.0.0/1")
                        && ips.iter().any(|&s| s == "128.0.0.0/1");
                    let has_v6_half =
                        ips.iter().any(|&s| s == "::/1") && ips.iter().any(|&s| s == "8000::/1");

                    for &ip in &ips {
                        if (ip == "0.0.0.0/1" || ip == "128.0.0.0/1") && has_v4_half {
                            continue;
                        }
                        if (ip == "::/1" || ip == "8000::/1") && has_v6_half {
                            continue;
                        }
                        new_ips.push(ip.to_string());
                    }
                    if has_v4_half && !new_ips.iter().any(|s| s == "0.0.0.0/0") {
                        new_ips.push("0.0.0.0/0".to_string());
                    }
                    if has_v6_half && !new_ips.iter().any(|s| s == "::/0") {
                        new_ips.push("::/0".to_string());
                    }
                } else {
                    let has_v4_zero = ips.iter().any(|&s| s == "0.0.0.0/0");
                    let has_v6_zero = ips.iter().any(|&s| s == "::/0");

                    for &ip in &ips {
                        if ip == "0.0.0.0/0" && has_v4_zero {
                            continue;
                        }
                        if ip == "::/0" && has_v6_zero {
                            continue;
                        }
                        new_ips.push(ip.to_string());
                    }
                    if has_v4_zero {
                        if !new_ips.iter().any(|s| s == "0.0.0.0/1") {
                            new_ips.push("0.0.0.0/1".to_string());
                        }
                        if !new_ips.iter().any(|s| s == "128.0.0.0/1") {
                            new_ips.push("128.0.0.0/1".to_string());
                        }
                    }
                    if has_v6_zero {
                        if !new_ips.iter().any(|s| s == "::/1") {
                            new_ips.push("::/1".to_string());
                        }
                        if !new_ips.iter().any(|s| s == "8000::/1") {
                            new_ips.push("8000::/1".to_string());
                        }
                    }
                }

                lines.push(format!("{} = {}", k.trim(), new_ips.join(", ")));
                continue;
            }
        }

        lines.push(line.to_string());
    }

    lines.join("\r\n")
}

/// Generates the default configuration template for a new tunnel with a fresh private key.
pub fn generate_new_tunnel_template() -> (String, String) {
    let private_key = Key::generate_private();
    let public_key = private_key.public().to_base64();
    let dummy_peer_key = Key::generate_private().public().to_base64();
    let template = format!(
        "[Interface]\r\nPrivateKey = {}\r\nAddress = 10.0.0.2/24\r\nDNS = 1.1.1.1\r\n\r\n[Peer]\r\nPublicKey = {}\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nEndpoint = 192.0.2.1:51820\r\n",
        private_key.to_base64(),
        dummy_peer_key
    );
    (template, public_key)
}

/// Internal dialog state and controls.
struct EditDialogState {
    hwnd: HWND,
    name_edit: HWND,
    pubkey_edit: HWND,
    config_edit: HWND,
    kill_switch_cb: HWND,
    save_btn: HWND,
    cancel_btn: HWND,
    lbl_name: HWND,
    lbl_pubkey: HWND,
    lbl_config: HWND,
    regular_font: HFONT,
    bold_font: HFONT,
    mono_font: HFONT,
    bg_brush: HBRUSH,
    is_closed: bool,
    result_config: Option<Config>,
    guard_kill_switch_change: bool,
    scratch_wide: Vec<u16>,
    scratch_text: String,
    last_pubkey_b64: Option<Option<[u8; 44]>>,
}

impl EditDialogState {
    fn on_config_text_changed(&mut self) {
        get_window_text_into(
            self.config_edit,
            &mut self.scratch_wide,
            &mut self.scratch_text,
        );
        let mut text = std::mem::take(&mut self.scratch_text);
        self.update_pubkey_from_text(&text);
        self.update_kill_switch_checkbox_from_text(&text);
        text.clear();
        self.scratch_text = text;
    }

    fn update_pubkey_from_text(&mut self, text: &str) {
        let mut key_buf = [0u8; 44];
        let next_key = extract_private_key(text)
            .and_then(|pk_b64| Key::from_base64(pk_b64).ok())
            .map(|key| {
                key.public().encode_base64(&mut key_buf);
                key_buf
            });

        if self.last_pubkey_b64 == Some(next_key) {
            return;
        }
        self.last_pubkey_b64 = Some(next_key);

        let display = match &self.last_pubkey_b64 {
            Some(Some(bytes)) => std::str::from_utf8(bytes).unwrap_or("(unknown)"),
            _ => "(unknown)",
        };
        set_window_text_with_buf(self.pubkey_edit, display, &mut self.scratch_wide);
    }

    fn update_kill_switch_checkbox_from_text(&mut self, text: &str) {
        if self.guard_kill_switch_change {
            return;
        }
        self.guard_kill_switch_change = true;
        if let Some(blocking) = evaluate_kill_switch_state(text) {
            unsafe {
                SendMessageW(
                    self.kill_switch_cb,
                    BM_SETCHECK,
                    if blocking { BST_CHECKED } else { BST_UNCHECKED } as usize,
                    0,
                );
            }
        }
        self.guard_kill_switch_change = false;
    }

    fn on_kill_switch_toggled(&mut self) {
        if self.guard_kill_switch_change {
            return;
        }
        self.guard_kill_switch_change = true;
        let checked =
            unsafe { SendMessageW(self.kill_switch_cb, BM_GETCHECK, 0, 0) } == BST_CHECKED as isize;
        get_window_text_into(
            self.config_edit,
            &mut self.scratch_wide,
            &mut self.scratch_text,
        );
        let new_text = toggle_kill_switch(&self.scratch_text, checked);
        set_window_text_with_buf(self.config_edit, &new_text, &mut self.scratch_wide);
        self.guard_kill_switch_change = false;
        self.update_pubkey_from_text(&new_text);
    }

    fn on_save(&mut self) {
        let mut raw_name = String::new();
        get_window_text_into(self.name_edit, &mut self.scratch_wide, &mut raw_name);
        let name = raw_name.trim().to_string();
        if name.is_empty() {
            show_dialog_message(
                self.hwnd,
                "A name is required.",
                "Invalid name",
                MB_OK | MB_ICONWARNING,
            );
            unsafe {
                SetFocus(self.name_edit);
            }
            return;
        }

        if !wireguard_conf::tunnel_name_is_valid(&name) {
            let msg = format!(
                "Tunnel name ‘{name}’ is invalid.\n\n\
                 Tunnel names must be 1 to 32 characters, consisting only of letters, numbers, _, =, +, ., and -.\n\
                 They cannot start or end with a period, and cannot be a reserved device name."
            );
            show_dialog_message(self.hwnd, &msg, "Invalid name", MB_OK | MB_ICONWARNING);
            unsafe {
                SetFocus(self.name_edit);
            }
            return;
        }

        get_window_text_into(
            self.config_edit,
            &mut self.scratch_wide,
            &mut self.scratch_text,
        );
        let parsed = wireguard_conf::parse_config_with_name(&self.scratch_text, &name);

        match parsed {
            Ok(mut config) => {
                config.name = name;

                // Attempt saving to the manager's encrypted config directory under LocalSystem
                let cfg_clone = config.clone();
                let saved = wireguard_elevate::do_as_system(move || {
                    if let Ok(dir) = wireguard_manager::ConfigDir::open_default() {
                        let _ = dir.save_config(&cfg_clone, true);
                    }
                    Ok(())
                });
                if saved.is_err() {
                    if let Ok(dir) = wireguard_manager::ConfigDir::open_default() {
                        let _ = dir.save_config(&config, true);
                    }
                }

                self.result_config = Some(config);
                self.is_closed = true;
                unsafe {
                    DestroyWindow(self.hwnd);
                }
            }
            Err(e) => {
                let msg = format!("Unable to create new configuration:\n\n{e}");
                show_dialog_message(self.hwnd, &msg, "Invalid configuration", MB_OK | MB_ICONERROR);
                unsafe {
                    SetFocus(self.config_edit);
                }
            }
        }
    }

    fn on_cancel(&mut self) {
        self.result_config = None;
        self.is_closed = true;
        unsafe {
            DestroyWindow(self.hwnd);
        }
    }

    fn layout(&self, width: i32, height: i32) {
        let margin_x = 15;
        let label_w = 80;
        let edit_x = margin_x + label_w + 10;
        let edit_w = (width - edit_x - margin_x).max(100);

        // Name row
        unsafe {
            MoveWindow(self.lbl_name, margin_x, 15, label_w, 20, 1);
            MoveWindow(self.name_edit, edit_x, 13, edit_w, 23, 1);
        }

        // Public key row
        unsafe {
            MoveWindow(self.lbl_pubkey, margin_x, 43, label_w, 20, 1);
            MoveWindow(self.pubkey_edit, edit_x, 41, edit_w, 23, 1);
        }

        // Configuration multiline edit
        let config_top = 70;
        let bottom_bar_height = 45;
        let config_h = (height - config_top - bottom_bar_height - 20).max(100);
        let config_w = (width - margin_x * 2).max(100);

        unsafe {
            MoveWindow(self.lbl_config, margin_x, config_top, 150, 18, 1);
            MoveWindow(self.config_edit, margin_x, config_top + 20, config_w, config_h, 1);
        }

        // Bottom row controls
        let bottom_y = height - bottom_bar_height;
        let btn_w = 85;
        let btn_h = 26;
        let cancel_x = width - margin_x - btn_w;
        let save_x = cancel_x - 10 - btn_w;
        let cb_w = (save_x - margin_x - 10).max(150);

        unsafe {
            MoveWindow(self.kill_switch_cb, margin_x, bottom_y + 2, cb_w, 24, 1);
            MoveWindow(self.save_btn, save_x, bottom_y, btn_w, btn_h, 1);
            MoveWindow(self.cancel_btn, cancel_x, bottom_y, btn_w, btn_h, 1);
        }
    }
}

/// Displays the Edit/Add Tunnel dialog modally and returns the parsed `Config` if saved.
///
/// If `existing_config` is `None`, creates a new tunnel with a freshly generated private key
/// and default template. If `Some`, loads the existing configuration for editing.
pub fn run_edit_dialog(
    parent: HWND,
    existing_config: Option<&wireguard_conf::Config>,
) -> Option<wireguard_conf::Config> {
    let hinstance = unsafe { GetModuleHandleW(ptr::null()) };

    REGISTER_DIALOG_ONCE.call_once(|| {
        with_wide_null(EDIT_DIALOG_CLASS_NAME, |class_ptr| {
            let mut wc: WNDCLASSEXW = unsafe { std::mem::zeroed() };
            wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
            wc.lpfnWndProc = Some(edit_dialog_wndproc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_ptr;
            wc.hCursor = unsafe { LoadCursorW(ptr::null_mut(), IDC_ARROW) };
            wc.hbrBackground = (COLOR_BTNFACE + 1) as HBRUSH;
            unsafe {
                RegisterClassExW(&wc);
            }
        });
    });

    let title_str = if existing_config.is_none() {
        "Create new tunnel"
    } else {
        "Edit tunnel"
    };

    let dlg_w = 620;
    let dlg_h = 520;

    let dlg_hwnd = with_wide_null(EDIT_DIALOG_CLASS_NAME, |class_ptr| {
        with_wide_null(title_str, |title_ptr| unsafe {
            CreateWindowExW(
                WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
                class_ptr,
                title_ptr,
                WS_POPUP
                    | WS_CAPTION
                    | WS_SYSMENU
                    | WS_THICKFRAME
                    | WS_MINIMIZEBOX
                    | WS_MAXIMIZEBOX
                    | WS_CLIPCHILDREN
                    | WS_VISIBLE,
                0,
                0,
                dlg_w,
                dlg_h,
                parent,
                ptr::null_mut(),
                hinstance,
                ptr::null(),
            )
        })
    });

    if dlg_hwnd.is_null() {
        return None;
    }

    // Center dialog over parent window or screen
    unsafe {
        let mut rc_parent: RECT = std::mem::zeroed();
        let mut rc_dlg: RECT = std::mem::zeroed();
        GetWindowRect(dlg_hwnd, &mut rc_dlg);
        let actual_w = rc_dlg.right - rc_dlg.left;
        let actual_h = rc_dlg.bottom - rc_dlg.top;

        if !parent.is_null() && IsWindow(parent) != 0 {
            GetWindowRect(parent, &mut rc_parent);
            let parent_w = rc_parent.right - rc_parent.left;
            let parent_h = rc_parent.bottom - rc_parent.top;
            let x = rc_parent.left + (parent_w - actual_w) / 2;
            let y = rc_parent.top + (parent_h - actual_h) / 2;
            SetWindowPos(
                dlg_hwnd,
                ptr::null_mut(),
                x.max(0),
                y.max(0),
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
        } else {
            let scr_w = GetSystemMetrics(SM_CXSCREEN);
            let scr_h = GetSystemMetrics(SM_CYSCREEN);
            let x = (scr_w - actual_w) / 2;
            let y = (scr_h - actual_h) / 2;
            SetWindowPos(
                dlg_hwnd,
                ptr::null_mut(),
                x.max(0),
                y.max(0),
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }

    // Fonts and brushes
    let bg_brush = unsafe { CreateSolidBrush(GetSysColor(COLOR_BTNFACE)) };
    let (regular_font, bold_font) = with_wide_null("Segoe UI", |font_ptr| unsafe {
        let regular = CreateFontW(
            -12, 0, 0, 0, FW_NORMAL as i32, 0, 0, 0,
            DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32, DEFAULT_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            font_ptr,
        );
        let bold = CreateFontW(
            -12, 0, 0, 0, FW_BOLD as i32, 0, 0, 0,
            DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32, DEFAULT_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            font_ptr,
        );
        (regular, bold)
    });
    let mono_font = with_wide_null("Consolas", |mono_ptr| unsafe {
        CreateFontW(
            -13, 0, 0, 0, FW_NORMAL as i32, 0, 0, 0,
            DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32, DEFAULT_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            mono_ptr,
        )
    });

    // Controls creation
    let (lbl_name, lbl_pubkey, lbl_config) = with_wide_null("STATIC", |static_ptr| {
        let l1 = with_wide_null("&Name:", |text_ptr| unsafe {
            CreateWindowExW(
                0, static_ptr, text_ptr,
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                dlg_hwnd, ptr::null_mut(), hinstance, ptr::null(),
            )
        });
        let l2 = with_wide_null("&Public key:", |text_ptr| unsafe {
            CreateWindowExW(
                0, static_ptr, text_ptr,
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                dlg_hwnd, ptr::null_mut(), hinstance, ptr::null(),
            )
        });
        let l3 = with_wide_null("&Configuration:", |text_ptr| unsafe {
            CreateWindowExW(
                0, static_ptr, text_ptr,
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                dlg_hwnd, ptr::null_mut(), hinstance, ptr::null(),
            )
        });
        (l1, l2, l3)
    });

    let (name_edit, pubkey_edit, config_edit) = with_wide_null("EDIT", |edit_ptr| {
        with_wide_null("", |empty_ptr| unsafe {
            let n = CreateWindowExW(
                0, edit_ptr, empty_ptr,
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | (ES_AUTOHSCROLL as u32),
                0, 0, 0, 0,
                dlg_hwnd, IDC_NAME_EDIT as usize as _, hinstance, ptr::null(),
            );
            let p = CreateWindowExW(
                0, edit_ptr, empty_ptr,
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | (ES_AUTOHSCROLL as u32) | (ES_READONLY as u32),
                0, 0, 0, 0,
                dlg_hwnd, IDC_PUBKEY_EDIT as usize as _, hinstance, ptr::null(),
            );
            let c = CreateWindowExW(
                0, edit_ptr, empty_ptr,
                WS_CHILD
                    | WS_VISIBLE
                    | WS_BORDER
                    | WS_TABSTOP
                    | WS_VSCROLL
                    | WS_HSCROLL
                    | (ES_MULTILINE as u32)
                    | (ES_AUTOVSCROLL as u32)
                    | (ES_AUTOHSCROLL as u32)
                    | (ES_WANTRETURN as u32),
                0, 0, 0, 0,
                dlg_hwnd, IDC_CONFIG_EDIT as usize as _, hinstance, ptr::null(),
            );
            (n, p, c)
        })
    });

    let (kill_switch_cb, save_btn, cancel_btn) = with_wide_null("BUTTON", |btn_ptr| {
        let cb = with_wide_null("&Block untunneled traffic (kill-switch)", |text_ptr| unsafe {
            CreateWindowExW(
                0, btn_ptr, text_ptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_AUTOCHECKBOX as u32),
                0, 0, 0, 0,
                dlg_hwnd, IDC_KILL_SWITCH_CB as usize as _, hinstance, ptr::null(),
            )
        });
        let sb = with_wide_null("&Save", |text_ptr| unsafe {
            CreateWindowExW(
                0, btn_ptr, text_ptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
                0, 0, 0, 0,
                dlg_hwnd, IDC_SAVE_BTN as usize as _, hinstance, ptr::null(),
            )
        });
        let cb2 = with_wide_null("Cancel", |text_ptr| unsafe {
            CreateWindowExW(
                0, btn_ptr, text_ptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                0, 0, 0, 0,
                dlg_hwnd, IDC_CANCEL_BTN as usize as _, hinstance, ptr::null(),
            )
        });
        (cb, sb, cb2)
    });

    // Apply fonts
    unsafe {
        SendMessageW(lbl_name, WM_SETFONT, bold_font as usize, 1);
        SendMessageW(name_edit, WM_SETFONT, regular_font as usize, 1);
        SendMessageW(lbl_pubkey, WM_SETFONT, bold_font as usize, 1);
        SendMessageW(pubkey_edit, WM_SETFONT, regular_font as usize, 1);
        SendMessageW(lbl_config, WM_SETFONT, bold_font as usize, 1);
        SendMessageW(config_edit, WM_SETFONT, mono_font as usize, 1);
        SendMessageW(kill_switch_cb, WM_SETFONT, regular_font as usize, 1);
        SendMessageW(save_btn, WM_SETFONT, regular_font as usize, 1);
        SendMessageW(cancel_btn, WM_SETFONT, regular_font as usize, 1);
    }

    let mut state = Box::new(EditDialogState {
        hwnd: dlg_hwnd,
        name_edit,
        pubkey_edit,
        config_edit,
        kill_switch_cb,
        save_btn,
        cancel_btn,
        lbl_name,
        lbl_pubkey,
        lbl_config,
        regular_font,
        bold_font,
        mono_font,
        bg_brush,
        is_closed: false,
        result_config: None,
        guard_kill_switch_change: false,
        scratch_wide: Vec::with_capacity(1024),
        scratch_text: String::with_capacity(1024),
        last_pubkey_b64: None,
    });

    // Populate initial values
    if let Some(existing) = existing_config {
        set_window_text_with_buf(state.name_edit, &existing.name, &mut state.scratch_wide);
        let raw_conf = wireguard_conf::to_wg_quick(existing);
        let conf_text = normalize_newlines_to_crlf(&raw_conf);
        set_window_text_with_buf(state.config_edit, &conf_text, &mut state.scratch_wide);
        state.update_pubkey_from_text(&conf_text);
        state.update_kill_switch_checkbox_from_text(&conf_text);
        unsafe {
            SetFocus(state.config_edit);
            SendMessageW(state.config_edit, EM_SETSEL, 0, 0);
        }
    } else {
        let (template, _pubkey) = generate_new_tunnel_template();
        set_window_text_with_buf(state.config_edit, &template, &mut state.scratch_wide);
        state.update_pubkey_from_text(&template);
        unsafe {
            SendMessageW(state.kill_switch_cb, BM_SETCHECK, BST_CHECKED as usize, 0);
            SetFocus(state.name_edit);
        }
    }

    // Initial layout
    let mut rc_client: RECT = unsafe { std::mem::zeroed() };
    unsafe {
        GetClientRect(dlg_hwnd, &mut rc_client);
    }
    state.layout(rc_client.right - rc_client.left, rc_client.bottom - rc_client.top);

    let state_ptr: *mut EditDialogState = &mut *state;
    unsafe {
        SetWindowLongPtrW(dlg_hwnd, GWLP_USERDATA, state_ptr as isize);
    }

    // Modal loop
    let is_parent_valid = !parent.is_null() && unsafe { IsWindow(parent) != 0 };
    if is_parent_valid {
        unsafe {
            EnableWindow(parent, FALSE);
        }
    }

    let mut msg: MSG = unsafe { std::mem::zeroed() };
    while !state.is_closed {
        let ret = unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) };
        if ret <= 0 {
            break;
        }

        unsafe {
            let focus = GetFocus();
            let is_multiline = focus == state.config_edit;

            // Allow multiline edit box to process Enter and Tab normally
            if is_multiline
                && msg.message == WM_KEYDOWN
                && (msg.wParam == VK_RETURN as usize || msg.wParam == VK_TAB as usize)
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
                continue;
            }

            if IsDialogMessageW(dlg_hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    if is_parent_valid {
        unsafe {
            EnableWindow(parent, TRUE);
            SetForegroundWindow(parent);
            SetFocus(parent);
        }
    }

    // Free GDI handles
    unsafe {
        if !state.bg_brush.is_null() {
            DeleteObject(state.bg_brush as HGDIOBJ);
        }
        if !state.regular_font.is_null() {
            DeleteObject(state.regular_font as HGDIOBJ);
        }
        if !state.bold_font.is_null() {
            DeleteObject(state.bold_font as HGDIOBJ);
        }
        if !state.mono_font.is_null() {
            DeleteObject(state.mono_font as HGDIOBJ);
        }
    }

    state.result_config.take()
}

/// Window procedure for `EditDialog`.
unsafe extern "system" fn edit_dialog_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut EditDialogState;

    match msg {
        WM_CTLCOLORSTATIC => {
            let hdc = wparam as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
            if !state_ptr.is_null() {
                return (*state_ptr).bg_brush as isize;
            }
            GetStockObject(NULL_BRUSH as i32) as isize
        }
        WM_CTLCOLOREDIT => {
            if !state_ptr.is_null() {
                let edit_hwnd = lparam as HWND;
                if edit_hwnd == (*state_ptr).pubkey_edit {
                    let hdc = wparam as HDC;
                    SetBkMode(hdc, TRANSPARENT as i32);
                    SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
                    return (*state_ptr).bg_brush as isize;
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_COMMAND => {
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                let id = (wparam & 0xFFFF) as u16;
                let notification = ((wparam >> 16) & 0xFFFF) as u32;

                match id {
                    IDC_SAVE_BTN => {
                        state.on_save();
                        return 0;
                    }
                    IDC_CANCEL_BTN => {
                        state.on_cancel();
                        return 0;
                    }
                    IDC_KILL_SWITCH_CB => {
                        if notification == BN_CLICKED {
                            state.on_kill_switch_toggled();
                        }
                    }
                    IDC_CONFIG_EDIT => {
                        if notification == EN_CHANGE {
                            state.on_config_text_changed();
                        }
                    }
                    _ => {}
                }
            }
            0
        }
        WM_SIZE => {
            if !state_ptr.is_null() {
                let w = (lparam & 0xFFFF) as i32;
                let h = ((lparam >> 16) & 0xFFFF) as i32;
                (*state_ptr).layout(w, h);
            }
            0
        }
        WM_GETMINMAXINFO => {
            let mmi = &mut *(lparam as *mut MINMAXINFO);
            mmi.ptMinTrackSize.x = 480;
            mmi.ptMinTrackSize.y = 380;
            0
        }
        WM_CLOSE => {
            if !state_ptr.is_null() {
                (*state_ptr).on_cancel();
            } else {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            if !state_ptr.is_null() {
                (*state_ptr).is_closed = true;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.192.122.1/24
ListenPort = 51820
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.95.5.67:1234
"#;

    #[test]
    fn test_extract_private_key() {
        let pk = extract_private_key(SAMPLE_CONFIG);
        assert_eq!(pk, Some("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));

        let key = Key::from_base64(pk.unwrap()).expect("key must parse");
        let pub_key = key.public().to_base64();
        assert!(!pub_key.is_empty());
    }

    #[test]
    fn test_generate_new_tunnel_template() {
        let (template, pubkey) = generate_new_tunnel_template();
        assert!(template.contains("[Interface]"));
        assert!(template.contains("[Peer]"));
        assert!(template.contains("PrivateKey = "));
        assert!(template.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(!pubkey.is_empty());

        let parsed = wireguard_conf::parse_config_with_name(&template, "new-tunnel");
        assert!(parsed.is_ok(), "template must parse with valid tunnel name");
    }

    #[test]
    fn test_kill_switch_state_and_toggle() {
        let state = evaluate_kill_switch_state(SAMPLE_CONFIG);
        assert_eq!(state, Some(true), "Sample config with 0.0.0.0/0 must evaluate to blocking");

        let unblocked = toggle_kill_switch(SAMPLE_CONFIG, false);
        assert!(unblocked.contains("0.0.0.0/1, 128.0.0.0/1"));
        assert!(unblocked.contains("::/1, 8000::/1"));

        let unblocked_state = evaluate_kill_switch_state(&unblocked);
        assert_eq!(unblocked_state, Some(false), "Unblocked text must evaluate to false");

        let reblocked = toggle_kill_switch(&unblocked, true);
        let reblocked_state = evaluate_kill_switch_state(&reblocked);
        assert_eq!(reblocked_state, Some(true), "Reblocked text must evaluate to true");
    }

    #[test]
    fn test_tunnel_name_validation() {
        assert!(wireguard_conf::tunnel_name_is_valid("wg0"));
        assert!(wireguard_conf::tunnel_name_is_valid("office_vpn-1"));
        assert!(!wireguard_conf::tunnel_name_is_valid("has space"));
        assert!(!wireguard_conf::tunnel_name_is_valid(".leading_dot"));
        assert!(!wireguard_conf::tunnel_name_is_valid("trailing_dot."));
        assert!(!wireguard_conf::tunnel_name_is_valid("CON"));
        assert!(!wireguard_conf::tunnel_name_is_valid(""));
    }

    #[test]
    fn test_normalize_newlines_to_crlf() {
        assert_eq!(normalize_newlines_to_crlf(""), "");
        assert_eq!(normalize_newlines_to_crlf("a\nb\nc"), "a\r\nb\r\nc");
        assert_eq!(normalize_newlines_to_crlf("a\r\nb\r\nc"), "a\r\nb\r\nc");
        assert_eq!(normalize_newlines_to_crlf("\na\r\nb\n"), "\r\na\r\nb\r\n");
    }
}
