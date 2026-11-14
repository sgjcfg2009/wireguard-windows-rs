// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! System Tray wrapper and notification icon management for WireGuard Windows.
//!
//! Provides the system notification area icon (using Win32 `Shell_NotifyIconW`),
//! contextual popup menu, status tooltips, and user interaction handling
//! (left-click raise, tunnel toggle, menu commands).
//! Faithfully mirrors `wireguard-windows/ui/tray.go`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::ptr;
use tracing::{info, warn};

use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP,
    NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, HICON,
    PostMessageW, PostQuitMessage, SetForegroundWindow, SetMenuDefaultItem,
    TrackPopupMenuEx, MF_CHECKED, MF_DISABLED, MF_GRAYED, MF_SEPARATOR, MF_STRING,
    MF_UNCHECKED, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_CONTEXTMENU,
    WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_USER,
};

pub use wireguard_types::TunnelState;
use crate::icons::{icon_for_state, icon_with_overlay_for_state, SafeIcon};
use crate::win32_util::{encode_wide_null_fixed, encode_wide_null_into};

/// Callback message ID sent by the tray notification icon to the window procedure.
/// Configured to `WM_USER + 0x3520` (0x3920 / 14624).
pub const WM_TRAY_CALLBACK: u32 = WM_USER + 0x3520;

/// Identifier for the WireGuard notification icon within its window.
pub const TRAY_ICON_UID: u32 = 1;

/// Tray popup menu command IDs
pub const ID_TRAY_STATUS: usize = 1000;
pub const ID_TRAY_MANAGE: usize = 1001;
pub const ID_TRAY_IMPORT: usize = 1002;
pub const ID_TRAY_ABOUT: usize = 1003;
pub const ID_TRAY_EXIT: usize = 1004;
pub const ID_TRAY_TUNNEL_BASE: usize = 2000;

/// Errors that may occur during system tray operations.
#[derive(Debug, thiserror::Error)]
pub enum TrayError {
    #[error("Invalid or null window handle")]
    InvalidWindow,

    #[error("Shell_NotifyIconW call failed: {0}")]
    ShellNotify(String),

    #[error("Icon creation failed: {0}")]
    Icon(String),

    #[error("Win32 error: {0}")]
    Win32(String),
}

pub type Result<T> = std::result::Result<T, TrayError>;

/// Represents an installed tunnel item in the dynamic tray context menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayTunnel {
    pub name: String,
    pub active: bool,
}

/// Cached icon category corresponding to WireGuard tray visual states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayIconKind {
    Active,
    Inactive,
    Stopped,
    Pending,
}

impl TrayIconKind {
    #[inline]
    fn from_tunnel_state(state: TunnelState) -> Self {
        match state {
            TunnelState::Started => Self::Active,
            TunnelState::Stopped => Self::Stopped,
            TunnelState::Starting | TunnelState::Stopping => Self::Pending,
            TunnelState::Unknown => Self::Inactive,
        }
    }

    #[inline]
    fn canonical_state(self) -> TunnelState {
        match self {
            Self::Active => TunnelState::Started,
            Self::Inactive => TunnelState::Unknown,
            Self::Stopped => TunnelState::Stopped,
            Self::Pending => TunnelState::Starting,
        }
    }
}

#[inline]
fn default_tooltip_for_state(state: TunnelState) -> &'static str {
    match state {
        TunnelState::Started => "WireGuard: Active",
        TunnelState::Starting => "WireGuard: Activating…",
        TunnelState::Stopping => "WireGuard: Deactivating…",
        TunnelState::Stopped => "WireGuard: Deactivated",
        TunnelState::Unknown => "WireGuard: Unknown",
    }
}

#[inline]
fn is_tunnel_active_state(state: TunnelState) -> bool {
    state == TunnelState::Started || state == TunnelState::Starting
}

/// System Tray notification icon and context menu wrapper.
pub struct Tray {
    hwnd: HWND,
    uid: u32,
    active: bool,
    last_state: Option<TunnelState>,
    current_icon_kind: Option<TrayIconKind>,
    active_tunnel_names: Vec<String>,
    tooltip: String,
    sz_tip: [u16; 128],
    icon_active: Option<SafeIcon>,
    icon_inactive: Option<SafeIcon>,
    icon_stopped: Option<SafeIcon>,
    icon_pending: Option<SafeIcon>,
    tunnels: Vec<TrayTunnel>,
    menu_buf: Vec<u16>,
    visible: bool,
    on_manage: Option<Box<dyn FnMut()>>,
    on_import: Option<Box<dyn FnMut()>>,
    on_about: Option<Box<dyn FnMut()>>,
    on_exit: Option<Box<dyn FnMut()>>,
    on_tunnel_toggle: Option<Box<dyn FnMut(&str, bool)>>,
}

impl Tray {
    /// Creates and registers a new system tray notification icon for the specified window `hwnd`.
    ///
    /// Initially sets state to Deactivated with the stopped shield icon and tooltip.
    pub fn new(hwnd: HWND) -> Result<Self> {
        if hwnd.is_null() {
            return Err(TrayError::InvalidWindow);
        }

        let icon_stopped = icon_with_overlay_for_state(TunnelState::Stopped, 16)
            .or_else(|_| icon_for_state(TunnelState::Stopped, 16))
            .map_err(TrayError::Icon)?;
        let tooltip = "WireGuard: Deactivated".to_string();
        let mut sz_tip = [0u16; 128];
        encode_wide_null_fixed(&tooltip, &mut sz_tip);

        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_UID;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY_CALLBACK;
        nid.hIcon = icon_stopped.handle();
        nid.szTip = sz_tip;

        let mut ok = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
        if ok == 0 {
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &nid);
                ok = Shell_NotifyIconW(NIM_ADD, &nid);
                if ok == 0 {
                    ok = Shell_NotifyIconW(NIM_MODIFY, &nid);
                }
            }
        }
        if ok == 0 {
            return Err(TrayError::ShellNotify(
                "Shell_NotifyIconW(NIM_ADD) failed to install tray icon".to_string(),
            ));
        }

        Ok(Self {
            hwnd,
            uid: TRAY_ICON_UID,
            active: false,
            last_state: Some(TunnelState::Stopped),
            current_icon_kind: Some(TrayIconKind::Stopped),
            active_tunnel_names: Vec::new(),
            tooltip,
            sz_tip,
            icon_active: None,
            icon_inactive: None,
            icon_stopped: Some(icon_stopped),
            icon_pending: None,
            tunnels: Vec::new(),
            menu_buf: Vec::with_capacity(64),
            visible: true,
            on_manage: None,
            on_import: None,
            on_about: None,
            on_exit: None,
            on_tunnel_toggle: None,
        })
    }

    /// Returns a cached Win32 `HICON` handle for `kind`, lazily creating it at most once.
    fn icon_handle_for(&mut self, kind: TrayIconKind) -> HICON {
        let slot = match kind {
            TrayIconKind::Active => &mut self.icon_active,
            TrayIconKind::Inactive => &mut self.icon_inactive,
            TrayIconKind::Stopped => &mut self.icon_stopped,
            TrayIconKind::Pending => &mut self.icon_pending,
        };
        if slot.is_none() {
            let state = kind.canonical_state();
            if let Ok(icon) = icon_with_overlay_for_state(state, 16)
                .or_else(|_| icon_for_state(state, 16))
            {
                *slot = Some(icon);
            }
        }
        slot.as_ref().map(|i| i.handle()).unwrap_or(ptr::null_mut())
    }

    /// Applies an icon + cached tooltip update via `Shell_NotifyIconW(NIM_MODIFY)` if visible.
    fn commit_icon_and_tooltip(&mut self, kind: TrayIconKind) {
        let icon_handle = self.icon_handle_for(kind);
        self.current_icon_kind = Some(kind);

        if self.visible && !self.hwnd.is_null() {
            let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = self.hwnd;
            nid.uID = self.uid;
            nid.uFlags = NIF_ICON | NIF_TIP;
            nid.hIcon = icon_handle;
            nid.szTip = self.sz_tip;

            unsafe {
                Shell_NotifyIconW(NIM_MODIFY, &nid);
            }
        }
    }

    /// Updates the operational state of the tray icon (icon image, active flag, and tooltip).
    ///
    /// If `tooltip` is empty, it formats automatically as `"WireGuard: Active"` or
    /// `"WireGuard: Deactivated"`. Unchanged updates are a no-op with zero allocations or syscalls.
    pub fn set_state(&mut self, active: bool, tooltip: &str) {
        let target_state = if active {
            TunnelState::Started
        } else {
            TunnelState::Stopped
        };
        let target_kind = if active {
            TrayIconKind::Active
        } else {
            TrayIconKind::Stopped
        };
        let target_tooltip = if tooltip.is_empty() {
            if active {
                "WireGuard: Active"
            } else {
                "WireGuard: Deactivated"
            }
        } else {
            tooltip
        };

        if self.active == active
            && self.last_state == Some(target_state)
            && self.current_icon_kind == Some(target_kind)
            && self.tooltip == target_tooltip
        {
            return;
        }

        self.active = active;
        self.last_state = Some(target_state);
        if self.tooltip != target_tooltip {
            self.tooltip.clear();
            self.tooltip.push_str(target_tooltip);
            encode_wide_null_fixed(&self.tooltip, &mut self.sz_tip);
        }

        self.commit_icon_and_tooltip(target_kind);
    }

    /// Updates the tray state using a full `TunnelState` enum.
    ///
    /// Uses cached overlay icons and cached tooltip state; unchanged updates perform zero
    /// allocations, zero GDI calls, and zero `Shell_NotifyIconW` calls.
    pub fn set_tunnel_state(&mut self, state: TunnelState, tooltip: Option<&str>) {
        let is_active = state == TunnelState::Started;
        let target_kind = TrayIconKind::from_tunnel_state(state);
        let target_tooltip = match tooltip {
            Some(t) if !t.is_empty() => t,
            _ => default_tooltip_for_state(state),
        };

        if self.active == is_active
            && self.last_state == Some(state)
            && self.current_icon_kind == Some(target_kind)
            && self.tooltip == target_tooltip
        {
            return;
        }

        self.active = is_active;
        self.last_state = Some(state);
        if self.tooltip != target_tooltip {
            self.tooltip.clear();
            self.tooltip.push_str(target_tooltip);
            encode_wide_null_fixed(&self.tooltip, &mut self.sz_tip);
        }

        self.commit_icon_and_tooltip(target_kind);
    }

    /// Synchronizes tray icon, tooltip, active tunnel names, and context menu list in one pass.
    ///
    /// When state, active tunnel names, and tunnel list entries are unchanged, performs zero
    /// `format!`, zero heap allocation, zero UTF-16 conversion, and zero `Shell_NotifyIconW` calls.
    pub fn sync_tunnel_states<'a, I>(&mut self, items: I)
    where
        I: Iterator<Item = (&'a str, TunnelState)> + Clone,
    {
        let mut any_started = false;
        let mut any_starting = false;
        let mut any_stopping = false;
        let mut active_count = 0usize;
        let mut active_names_match = true;
        let mut total_count = 0usize;
        let mut menu_matches = true;

        for (name, state) in items.clone() {
            match state {
                TunnelState::Started => any_started = true,
                TunnelState::Starting => any_starting = true,
                TunnelState::Stopping => any_stopping = true,
                TunnelState::Stopped | TunnelState::Unknown => {}
            }

            let is_active = is_tunnel_active_state(state);
            if is_active {
                if active_names_match {
                    match self.active_tunnel_names.get(active_count) {
                        Some(prev) if prev == name => {}
                        _ => active_names_match = false,
                    }
                }
                active_count += 1;
            }

            if menu_matches {
                match self.tunnels.get(total_count) {
                    Some(prev) if prev.active == is_active && prev.name == name => {}
                    _ => menu_matches = false,
                }
            }
            total_count += 1;
        }

        if active_count != self.active_tunnel_names.len() {
            active_names_match = false;
        }
        if total_count != self.tunnels.len() {
            menu_matches = false;
        }

        let overall_state = if any_started {
            TunnelState::Started
        } else if any_starting {
            TunnelState::Starting
        } else if any_stopping {
            TunnelState::Stopping
        } else {
            TunnelState::Stopped
        };
        let target_kind = TrayIconKind::from_tunnel_state(overall_state);

        if self.last_state != Some(overall_state)
            || self.current_icon_kind != Some(target_kind)
            || !active_names_match
        {
            self.active_tunnel_names.clear();
            for (name, state) in items.clone() {
                if is_tunnel_active_state(state) {
                    self.active_tunnel_names.push(name.to_string());
                }
            }

            self.active = any_started || any_starting;
            self.last_state = Some(overall_state);

            self.tooltip.clear();
            if let Some(first_name) = self.active_tunnel_names.first() {
                let prefix = match overall_state {
                    TunnelState::Starting => "WireGuard: Activating",
                    TunnelState::Stopping => "WireGuard: Deactivating",
                    _ => "WireGuard: Activated",
                };
                if self.active_tunnel_names.len() == 1 {
                    let _ = write!(&mut self.tooltip, "{prefix} ({first_name})");
                } else {
                    let _ = write!(&mut self.tooltip, "{prefix} (");
                    for (i, n) in self.active_tunnel_names.iter().enumerate() {
                        if i > 0 {
                            self.tooltip.push_str(", ");
                        }
                        self.tooltip.push_str(n);
                    }
                    self.tooltip.push(')');
                }
            } else {
                self.tooltip.push_str(default_tooltip_for_state(overall_state));
            }

            encode_wide_null_fixed(&self.tooltip, &mut self.sz_tip);
            self.commit_icon_and_tooltip(target_kind);
        }

        if !menu_matches {
            self.tunnels.clear();
            self.tunnels.reserve(total_count);
            for (name, state) in items {
                self.tunnels.push(TrayTunnel {
                    name: name.to_string(),
                    active: is_tunnel_active_state(state),
                });
            }
        }
    }

    /// Updates the dynamic list of tunnels displayed in the right-click popup context menu.
    ///
    /// Preserves existing active flags for tunnels that remain present.
    pub fn update_tunnels(&mut self, tunnels: &[String]) {
        if self.tunnels.len() == tunnels.len()
            && self
                .tunnels
                .iter()
                .zip(tunnels.iter())
                .all(|(a, b)| a.name == *b)
        {
            return;
        }

        let old_states: HashMap<String, bool> = self
            .tunnels
            .iter()
            .map(|t| (t.name.clone(), t.active))
            .collect();

        self.tunnels = tunnels
            .iter()
            .map(|name| {
                let active = old_states.get(name).copied().unwrap_or(false);
                TrayTunnel {
                    name: name.clone(),
                    active,
                }
            })
            .collect();
    }

    /// Updates the dynamic list of tunnels with explicit active states.
    pub fn update_tunnels_with_state(&mut self, tunnels: &[(String, bool)]) {
        if self.tunnels.len() == tunnels.len()
            && self
                .tunnels
                .iter()
                .zip(tunnels.iter())
                .all(|(a, (b_name, b_active))| a.active == *b_active && a.name == *b_name)
        {
            return;
        }

        self.tunnels.clear();
        self.tunnels.reserve(tunnels.len());
        for (name, active) in tunnels {
            self.tunnels.push(TrayTunnel {
                name: name.clone(),
                active: *active,
            });
        }
    }

    /// Sets the active flag for a specific tunnel by name.
    pub fn set_tunnel_active(&mut self, name: &str, active: bool) {
        if let Some(t) = self.tunnels.iter_mut().find(|t| t.name == name) {
            t.active = active;
        }
    }

    /// Unregisters and removes the tray icon from the Windows taskbar.
    pub fn dispose(&mut self) {
        if self.visible && !self.hwnd.is_null() {
            let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = self.hwnd;
            nid.uID = self.uid;
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &nid);
            }
            self.visible = false;
        }
    }

    /// Handles a tray notification callback message delivered to the parent window procedure.
    ///
    /// Matches `WM_LBUTTONUP`, `WM_LBUTTONDBLCLK`, `WM_RBUTTONUP`, and `WM_CONTEXTMENU`.
    /// Returns `true` if the message was handled.
    pub fn handle_tray_message(&mut self, lparam: isize) -> bool {
        let msg = (lparam as u32) & 0xFFFF;
        match msg {
            WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                self.on_left_click();
                true
            }
            WM_RBUTTONUP | WM_CONTEXTMENU => {
                self.show_context_menu();
                true
            }
            _ => false,
        }
    }

    /// Handler for left-click on the tray icon.
    ///
    /// Restores, unhides, and raises the Manage Tunnels window to the foreground,
    /// then triggers the `on_manage` callback if configured.
    pub fn on_left_click(&mut self) {
        crate::raise::raise(self.hwnd);
        if let Some(ref mut cb) = self.on_manage {
            cb();
        }
    }

    /// Displays the right-click popup context menu at the current cursor location.
    ///
    /// Constructs the 8 required items:
    /// 1. Status display (disabled/grayed header: "Status: Active" / "Status: Deactivated")
    /// 2. Dynamic list of installed tunnels with checkmarks (toggles active state on click)
    /// 3. Separator
    /// 4. "&Manage tunnels..." (Bold default item -> opens/raises main window)
    /// 5. "&Import tunnel(s) from file..."
    /// 6. Separator
    /// 7. "&About WireGuard..."
    /// 8. "E&xit" (Terminates application completely)
    pub fn show_context_menu(&mut self) {
        let mut pt = POINT { x: 0, y: 0 };
        unsafe {
            GetCursorPos(&mut pt);
            SetForegroundWindow(self.hwnd);
        }

        let hmenu = unsafe { CreatePopupMenu() };
        if hmenu.is_null() {
            warn!("Failed to create tray context popup menu");
            return;
        }

        // Item 1: Status display ("Status: Active" or "Status: Deactivated", disabled/grayed out header)
        let status_str = if self.active {
            "Status: Active"
        } else {
            "Status: Deactivated"
        };
        encode_wide_null_into(status_str, &mut self.menu_buf);
        unsafe {
            AppendMenuW(
                hmenu,
                MF_STRING | MF_DISABLED | MF_GRAYED,
                ID_TRAY_STATUS,
                self.menu_buf.as_ptr(),
            );
        }

        // Item 2: Dynamic list of installed tunnels with checkmarks
        if !self.tunnels.is_empty() {
            unsafe {
                AppendMenuW(hmenu, MF_SEPARATOR, 0, ptr::null());
            }
            for (i, tunnel) in self.tunnels.iter().enumerate() {
                let mut flags = MF_STRING;
                if tunnel.active {
                    flags |= MF_CHECKED;
                } else {
                    flags |= MF_UNCHECKED;
                }
                encode_wide_null_into(&tunnel.name, &mut self.menu_buf);
                unsafe {
                    AppendMenuW(
                        hmenu,
                        flags,
                        ID_TRAY_TUNNEL_BASE + i,
                        self.menu_buf.as_ptr(),
                    );
                }
            }
        }

        // Item 3: Separator
        unsafe {
            AppendMenuW(hmenu, MF_SEPARATOR, 0, ptr::null());
        }

        // Item 4: "&Manage tunnels..." (Bold default item -> opens/raises main window)
        encode_wide_null_into("&Manage tunnels...", &mut self.menu_buf);
        unsafe {
            AppendMenuW(hmenu, MF_STRING, ID_TRAY_MANAGE, self.menu_buf.as_ptr());
            SetMenuDefaultItem(hmenu, ID_TRAY_MANAGE as u32, 0);
        }

        // Item 5: "&Import tunnel(s) from file..."
        encode_wide_null_into("&Import tunnel(s) from file...", &mut self.menu_buf);
        unsafe {
            AppendMenuW(hmenu, MF_STRING, ID_TRAY_IMPORT, self.menu_buf.as_ptr());
        }

        // Item 6: Separator
        unsafe {
            AppendMenuW(hmenu, MF_SEPARATOR, 0, ptr::null());
        }

        // Item 7: "&About WireGuard..."
        encode_wide_null_into("&About WireGuard...", &mut self.menu_buf);
        unsafe {
            AppendMenuW(hmenu, MF_STRING, ID_TRAY_ABOUT, self.menu_buf.as_ptr());
        }

        // Item 8: "E&xit" (Terminates application completely)
        encode_wide_null_into("E&xit", &mut self.menu_buf);
        unsafe {
            AppendMenuW(hmenu, MF_STRING, ID_TRAY_EXIT, self.menu_buf.as_ptr());
        }

        // Display popup menu and track selection synchronously
        let cmd = unsafe {
            TrackPopupMenuEx(
                hmenu,
                TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                pt.x,
                pt.y,
                self.hwnd,
                ptr::null(),
            )
        } as usize;

        unsafe {
            DestroyMenu(hmenu);
            PostMessageW(self.hwnd, WM_NULL, 0, 0);
        }

        if cmd != 0 {
            self.handle_menu_command(cmd);
        }
    }

    /// Dispatches a command selected from the tray popup context menu.
    pub fn handle_menu_command(&mut self, cmd: usize) {
        match cmd {
            ID_TRAY_MANAGE => {
                self.on_left_click();
            }
            ID_TRAY_IMPORT => {
                crate::raise::raise(self.hwnd);
                if let Some(ref mut cb) = self.on_import {
                    cb();
                }
            }
            ID_TRAY_ABOUT => {
                if let Some(ref mut cb) = self.on_about {
                    cb();
                }
            }
            ID_TRAY_EXIT => {
                if let Some(ref mut cb) = self.on_exit {
                    cb();
                }
                self.dispose();
                unsafe {
                    PostQuitMessage(0);
                }
            }
            _ if cmd >= ID_TRAY_TUNNEL_BASE => {
                let index = cmd - ID_TRAY_TUNNEL_BASE;
                if index < self.tunnels.len() {
                    self.tunnels[index].active = !self.tunnels[index].active;
                    let name = self.tunnels[index].name.clone();
                    let active = self.tunnels[index].active;
                    info!("Tray context menu toggled tunnel '{}' to active={}", name, active);
                    if let Some(ref mut cb) = self.on_tunnel_toggle {
                        cb(&name, active);
                    }
                }
            }
            _ => {}
        }
    }

    /// Displays a Windows system tray balloon notification.
    pub fn show_balloon(&mut self, title: &str, message: &str) -> Result<()> {
        if !self.visible || self.hwnd.is_null() {
            return Err(TrayError::InvalidWindow);
        }

        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = self.uid;
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        encode_wide_null_fixed(title, &mut nid.szInfoTitle);
        encode_wide_null_fixed(message, &mut nid.szInfo);

        let ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
        if ok == 0 {
            Err(TrayError::ShellNotify(
                "Shell_NotifyIconW balloon notification failed".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Sets the callback invoked when the user clicks "&Manage tunnels..." or left-clicks the tray.
    pub fn set_on_manage<F: FnMut() + 'static>(&mut self, f: F) {
        self.on_manage = Some(Box::new(f));
    }

    /// Sets the callback invoked when the user clicks "&Import tunnel(s) from file...".
    pub fn set_on_import<F: FnMut() + 'static>(&mut self, f: F) {
        self.on_import = Some(Box::new(f));
    }

    /// Sets the callback invoked when the user clicks "&About WireGuard...".
    pub fn set_on_about<F: FnMut() + 'static>(&mut self, f: F) {
        self.on_about = Some(Box::new(f));
    }

    /// Sets the callback invoked before application exit.
    pub fn set_on_exit<F: FnMut() + 'static>(&mut self, f: F) {
        self.on_exit = Some(Box::new(f));
    }

    /// Sets the callback invoked when a tunnel checkmark is toggled in the context menu.
    pub fn set_on_tunnel_toggle<F: FnMut(&str, bool) + 'static>(&mut self, f: F) {
        self.on_tunnel_toggle = Some(Box::new(f));
    }

    /// Returns `true` if WireGuard is currently marked active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the current tooltip text.
    pub fn tooltip(&self) -> &str {
        &self.tooltip
    }

    /// Returns the current list of tunnels.
    pub fn tunnels(&self) -> &[TrayTunnel] {
        &self.tunnels
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.dispose();
        self.icon_active = None;
        self.icon_inactive = None;
        self.icon_stopped = None;
        self.icon_pending = None;
    }
}

/// Brings the main Manage Tunnels window to the foreground and raises it.
///
/// Delegates to [`crate::raise::raise`].
#[inline]
pub fn raise_window(hwnd: HWND) {
    crate::raise::raise(hwnd);
}
