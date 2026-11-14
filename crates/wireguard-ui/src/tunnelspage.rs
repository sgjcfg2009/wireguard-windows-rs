// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Native Win32 Tunnels Page container for the WireGuard Windows interface.
//!
//! Provides the primary navigation page matching `wireguard-windows/ui/tunnelspage.go`:
//! - Left pane: fixed-width tunnel list view with bottom action buttons (Add Tunnel, Import).
//! - Right pane: dynamic stretching details container (confview) and action bar (Activate/Deactivate, Edit, Delete).
//! - Responsive layout management on `WM_SIZE`.
//! - Integrated tunnel management via IPC and DPAPI configuration store.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Once, OnceLock};

use windows_sys::Win32::Foundation::{
    FALSE, HWND, LPARAM, LRESULT, POINT, RECT, TRUE, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, DeleteDC,
    DeleteObject, DrawTextW, EndPaint, FillRect, GetSysColorBrush, InvalidateRect, SelectObject,
    SetBkMode, SetTextColor, COLOR_BTNFACE, COLOR_WINDOW, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE,
    DT_WORDBREAK, HBRUSH, HDC, HFONT, HGDIOBJ, PAINTSTRUCT, SRCCOPY, TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Services::{
    SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_ERROR_NORMAL, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_START_PENDING,
    SERVICE_NOTIFY_STOPPED, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::UI::Controls::NMHDR;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, GetClientRect,
    GetParent, GetWindowLongPtrW, MessageBoxW, MoveWindow, PeekMessageW, PostMessageW,
    RegisterClassExW, SendMessageW, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow,
    TrackPopupMenu, BS_PUSHBUTTON, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA, IDYES, MB_DEFBUTTON2,
    MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_YESNO, MF_STRING, MSG, PM_REMOVE, SWP_NOACTIVATE,
    SWP_NOZORDER, SW_HIDE, SW_SHOW, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_TOPALIGN, WM_COMMAND,
    WM_CTLCOLORBTN, WM_CTLCOLORSTATIC, WM_ERASEBKGND, WM_NCDESTROY, WM_NOTIFY, WM_PAINT,
    WM_SETFONT, WM_SIZE, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
    WS_TABSTOP, WS_VISIBLE,
};

use crate::listview::{ListViewNotification, TunnelItem, TunnelListView};
use crate::log_to_file;
use crate::win32_util::{
    to_wide_null, with_wide_null, WM_APP_SERVICE_STATE_CHANGED, WM_APP_TRAY_SYNC,
    WM_APP_TUNNEL_OP_DONE,
};
use wireguard_conf::parser::parse_config_bytes;
use wireguard_conf::service_name_of_tunnel;
use wireguard_conf::store::list_config_names;
use wireguard_manager::ConfigDir;
use wireguard_service::ScmHandle;
use wireguard_types::{TunnelConfig, TunnelState};

/// Registered Win32 window class names for the TunnelsPage composite and details container.
const TUNNELS_PAGE_CLASS: &str = "WireGuardTunnelsPage";
const DETAILS_VIEW_CLASS: &str = "WireGuardDetailsPlaceholder";

/// Control identifier constants for Win32 child controls.
const ID_BTN_ADD: usize = 1001;
const ID_BTN_IMPORT: usize = 1002;
const ID_BTN_TOGGLE: usize = 1003;
const ID_BTN_EDIT: usize = 1004;
const ID_BTN_DELETE: usize = 1005;
const ID_BTN_FILLER_IMPORT: usize = 1006;
const ID_MENU_IMPORT: usize = 2001;
const ID_MENU_ADD_EMPTY: usize = 2002;

/// Errors occurring during UI initialization or operations.
#[derive(Debug, thiserror::Error)]
pub enum UiError {
    #[error("Win32 error: {0}")]
    Win32(u32),
    #[error("Window creation failed: {0}")]
    WindowCreation(String),
    #[error("Control error: {0}")]
    Control(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration parse error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, UiError>;

static REGISTER_CLASSES: Once = Once::new();

/// Static NUL-terminated UTF-16 labels initialized once for the details view and toggle button.
struct DetailsLabels {
    status: Vec<u16>,
    active: Vec<u16>,
    activating: Vec<u16>,
    deactivating: Vec<u16>,
    inactive: Vec<u16>,
    pubkey: Vec<u16>,
    addresses: Vec<u16>,
    listen_port: Vec<u16>,
    dns: Vec<u16>,
    mtu: Vec<u16>,
    endpoint: Vec<u16>,
    allowed_ips: Vec<u16>,
    btn_activate: Vec<u16>,
    btn_deactivate: Vec<u16>,
}

fn details_labels() -> &'static DetailsLabels {
    static LABELS: OnceLock<DetailsLabels> = OnceLock::new();
    LABELS.get_or_init(|| DetailsLabels {
        status: to_wide_null("Status:"),
        active: to_wide_null("Active"),
        activating: to_wide_null("Activating..."),
        deactivating: to_wide_null("Deactivating..."),
        inactive: to_wide_null("Inactive"),
        pubkey: to_wide_null("Public key:"),
        addresses: to_wide_null("Addresses:"),
        listen_port: to_wide_null("Listen port:"),
        dns: to_wide_null("DNS servers:"),
        mtu: to_wide_null("MTU:"),
        endpoint: to_wide_null("Endpoint:"),
        allowed_ips: to_wide_null("Allowed IPs:"),
        btn_activate: to_wide_null("&Activate"),
        btn_deactivate: to_wide_null("&Deactivate"),
    })
}

/// Encodes `WireGuardTunnel$<name>\0` on the stack for typical tunnel names without allocating.
#[inline]
fn with_tunnel_service_name_wide<R>(name: &str, f: impl FnOnce(*const u16) -> R) -> R {
    const PREFIX: &str = "WireGuardTunnel$";
    let mut stack_buf = [0u16; 64];
    let mut len = 0usize;
    let mut overflow = false;

    for cu in PREFIX.encode_utf16().chain(name.encode_utf16()) {
        if len >= stack_buf.len() - 1 {
            overflow = true;
            break;
        }
        stack_buf[len] = cu;
        len += 1;
    }

    if overflow {
        let mut heap = Vec::with_capacity(PREFIX.len() + name.len() + 1);
        heap.extend(PREFIX.encode_utf16());
        heap.extend(name.encode_utf16());
        heap.push(0);
        f(heap.as_ptr())
    } else {
        stack_buf[len] = 0;
        f(stack_buf.as_ptr())
    }
}

fn show_error_box(parent: HWND, title: &str, msg: &str) {
    with_wide_null(title, |title_ptr| {
        with_wide_null(msg, |msg_ptr| unsafe {
            MessageBoxW(parent, msg_ptr, title_ptr, MB_OK | MB_ICONERROR);
        });
    });
}

fn confirm_warning_yes_no(parent: HWND, title: &str, msg: &str) -> bool {
    let ret = with_wide_null(title, |title_ptr| {
        with_wide_null(msg, |msg_ptr| unsafe {
            MessageBoxW(
                parent,
                msg_ptr,
                title_ptr,
                MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
            )
        })
    });
    ret == IDYES
}

fn post_tray_sync(page_hwnd: HWND) {
    if page_hwnd.is_null() {
        return;
    }
    unsafe {
        let parent = GetParent(page_hwnd);
        if !parent.is_null() {
            let _ = PostMessageW(parent, WM_APP_TRAY_SYNC, 0, 0);
        }
    }
}

/// Completion payloads posted back from background worker threads via `WM_APP_TUNNEL_OP_DONE`.
enum TunnelOpResult {
    AutostartSynced {
        any_started: bool,
    },
    Deactivated {
        tunnel_name: String,
        still_active: bool,
    },
    Activated {
        tunnel_name: String,
        error: Option<String>,
    },
    Deleted {
        tunnel_name: String,
    },
    ImportParsed {
        configs: Vec<TunnelConfig>,
        errors: Vec<String>,
    },
    Imported {
        configs: Vec<TunnelConfig>,
        last_imported: Option<String>,
        errors: Vec<String>,
    },
}

fn post_tunnel_op_result(target_hwnd_raw: isize, result: TunnelOpResult) {
    if target_hwnd_raw == 0 {
        return;
    }
    let ptr = Box::into_raw(Box::new(result));
    let posted = unsafe {
        PostMessageW(
            target_hwnd_raw as HWND,
            WM_APP_TUNNEL_OP_DONE,
            0,
            ptr as LPARAM,
        )
    };
    if posted == 0 {
        // Target window is already gone; reclaim heap payload instead of leaking.
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

/// Registers Win32 window classes for the TunnelsPage composite and details view.
fn ensure_window_classes_registered() -> Result<()> {
    let mut err = None;
    REGISTER_CLASSES.call_once(|| {
        let hinstance = unsafe { GetModuleHandleW(ptr::null()) };

        // 1. Tunnels Page main container class
        let reg_main = with_wide_null(TUNNELS_PAGE_CLASS, |class_ptr| {
            let mut wc: WNDCLASSEXW = unsafe { std::mem::zeroed() };
            wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
            wc.style = CS_HREDRAW | CS_VREDRAW;
            wc.lpfnWndProc = Some(tunnels_page_wndproc);
            wc.hInstance = hinstance;
            wc.hbrBackground = (COLOR_BTNFACE + 1) as HBRUSH;
            wc.lpszClassName = class_ptr;
            unsafe { RegisterClassExW(&wc) }
        });

        if reg_main == 0 {
            err = Some(UiError::WindowCreation(format!(
                "Failed to register class {TUNNELS_PAGE_CLASS}"
            )));
            return;
        }

        // 2. Details view container class
        let reg_details = with_wide_null(DETAILS_VIEW_CLASS, |details_class_ptr| {
            let mut wc_details: WNDCLASSEXW = unsafe { std::mem::zeroed() };
            wc_details.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
            wc_details.style = CS_HREDRAW | CS_VREDRAW;
            wc_details.lpfnWndProc = Some(details_view_wndproc);
            wc_details.hInstance = hinstance;
            wc_details.hbrBackground = (COLOR_WINDOW + 1) as HBRUSH;
            wc_details.lpszClassName = details_class_ptr;
            unsafe { RegisterClassExW(&wc_details) }
        });

        if reg_details == 0 {
            err = Some(UiError::WindowCreation(format!(
                "Failed to register class {DETAILS_VIEW_CLASS}"
            )));
        }
    });

    if let Some(e) = err {
        Err(e)
    } else {
        Ok(())
    }
}

/// Pre-formatted UTF-16 row for zero-allocation WM_PAINT rendering.
struct RenderedField {
    label: &'static [u16],
    value: Vec<u16>,
}

/// Pre-formatted UTF-16 peer section for zero-allocation WM_PAINT rendering.
struct RenderedPeer {
    title: Vec<u16>,
    fields: Vec<RenderedField>,
}

/// Cached UTF-16 representation of the selected tunnel's configuration.
#[derive(Default)]
struct RenderedDetailsCache {
    title: Vec<u16>,
    interface_fields: Vec<RenderedField>,
    peers: Vec<RenderedPeer>,
}

/// Internal state of the TunnelsPage composite.
struct TunnelsPageInner {
    hwnd: HWND,
    list_view: TunnelListView,
    btn_add: HWND,
    btn_import: HWND,
    details_container: HWND,
    btn_toggle: HWND,
    btn_edit: HWND,
    btn_delete: HWND,
    filler_container: HWND,
    _lbl_filler: HWND,
    _btn_filler_import: HWND,
    font: HFONT,
    font_bold: HFONT,
    font_large: HFONT,
    is_active: bool,
    selected_state: TunnelState,
    visible: bool,
    details_dirty: bool,
    paint_dirty: bool,
    showing_filler: Option<bool>,
    rendered_tunnel_name: Option<String>,
    current_config: Option<TunnelConfig>,
    rendered_details: RenderedDetailsCache,
    config_cache: HashMap<String, TunnelConfig>,
    pending_ops: HashSet<String>,
    scm: Option<ScmHandle>,
    width: i32,
    height: i32,
    in_batch_update: bool,
}

impl Drop for TunnelsPageInner {
    fn drop(&mut self) {
        unsafe {
            if !self.filler_container.is_null() {
                SetWindowLongPtrW(self.filler_container, GWLP_USERDATA, 0);
            }
            if !self.details_container.is_null() {
                SetWindowLongPtrW(self.details_container, GWLP_USERDATA, 0);
            }
            if !self.hwnd.is_null() {
                SetWindowLongPtrW(self.hwnd, GWLP_USERDATA, 0);
            }
            if !self.font.is_null() {
                DeleteObject(self.font as HGDIOBJ);
                self.font = ptr::null_mut();
            }
            if !self.font_bold.is_null() {
                DeleteObject(self.font_bold as HGDIOBJ);
                self.font_bold = ptr::null_mut();
            }
            if !self.font_large.is_null() {
                DeleteObject(self.font_large as HGDIOBJ);
                self.font_large = ptr::null_mut();
            }
        }
    }
}

/// The TunnelsPage Win32 composite widget managing tunnel listings, controls, and details.
pub struct TunnelsPage {
    inner: Box<TunnelsPageInner>,
}

impl TunnelsPage {
    /// Creates and initializes a new `TunnelsPage` container within the specified `parent` window.
    pub fn new(parent: HWND, rect: RECT) -> Result<Self> {
        log_to_file("TunnelsPage::new(): start");
        ensure_window_classes_registered()?;
        log_to_file("TunnelsPage::new(): window classes registered");

        let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
        let width = (rect.right - rect.left).max(200);
        let height = (rect.bottom - rect.top).max(150);

        let hwnd = with_wide_null(TUNNELS_PAGE_CLASS, |class_ptr| unsafe {
            CreateWindowExW(
                0,
                class_ptr,
                ptr::null(),
                WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                rect.left,
                rect.top,
                width,
                height,
                parent,
                ptr::null_mut(),
                hinstance,
                ptr::null(),
            )
        });

        if hwnd.is_null() {
            log_to_file("TunnelsPage::new(): CreateWindowExW failed");
            return Err(UiError::WindowCreation(
                "CreateWindowExW failed for TunnelsPage".to_string(),
            ));
        }
        log_to_file(&format!("TunnelsPage::new(): CreateWindowExW succeeded, HWND={:?}", hwnd));

        // Create standard UI fonts
        let (font, font_bold, font_large) = with_wide_null("Segoe UI", |font_ptr| unsafe {
            (
                CreateFontW(-12, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 0, 0, font_ptr),
                CreateFontW(-12, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 0, 0, font_ptr),
                CreateFontW(-16, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 0, 0, font_ptr),
            )
        });

        log_to_file("TunnelsPage::new(): creating TunnelListView...");
        // 1. Create Left Pane: Tunnel List View
        let list_view = TunnelListView::new(hwnd, 5, 5, 205, height - 44)
            .map_err(UiError::Control)?;
        log_to_file("TunnelsPage::new(): TunnelListView created");

        let labels = details_labels();

        // 2 & 4. Create Toolbar & Action Buttons
        let (btn_add, btn_import, btn_toggle, btn_edit, btn_delete) =
            with_wide_null("BUTTON", |btn_ptr| {
                let add = with_wide_null("&Add Tunnel", |text_ptr| unsafe {
                    CreateWindowExW(
                        0,
                        btn_ptr,
                        text_ptr,
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                        5,
                        height - 34,
                        100,
                        28,
                        hwnd,
                        ID_BTN_ADD as *mut _,
                        hinstance,
                        ptr::null(),
                    )
                });
                let import = with_wide_null("&Import…", |text_ptr| unsafe {
                    CreateWindowExW(
                        0,
                        btn_ptr,
                        text_ptr,
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                        110,
                        height - 34,
                        100,
                        28,
                        hwnd,
                        ID_BTN_IMPORT as *mut _,
                        hinstance,
                        ptr::null(),
                    )
                });
                let toggle = unsafe {
                    CreateWindowExW(
                        0,
                        btn_ptr,
                        labels.btn_activate.as_ptr(),
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                        218,
                        height - 38,
                        110,
                        30,
                        hwnd,
                        ID_BTN_TOGGLE as *mut _,
                        hinstance,
                        ptr::null(),
                    )
                };
                let edit = with_wide_null("&Edit", |text_ptr| unsafe {
                    CreateWindowExW(
                        0,
                        btn_ptr,
                        text_ptr,
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                        336,
                        height - 38,
                        80,
                        30,
                        hwnd,
                        ID_BTN_EDIT as *mut _,
                        hinstance,
                        ptr::null(),
                    )
                });
                let delete = with_wide_null("&Delete", |text_ptr| unsafe {
                    CreateWindowExW(
                        0,
                        btn_ptr,
                        text_ptr,
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                        424,
                        height - 38,
                        80,
                        30,
                        hwnd,
                        ID_BTN_DELETE as *mut _,
                        hinstance,
                        ptr::null(),
                    )
                });
                (add, import, toggle, edit, delete)
            });

        // 3 & 5. Create Right Pane: Details View & Empty State Containers
        let (details_container, filler_container) =
            with_wide_null(DETAILS_VIEW_CLASS, |details_ptr| unsafe {
                let details = CreateWindowExW(
                    0,
                    details_ptr,
                    ptr::null(),
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                    218,
                    5,
                    (width - 223).max(50),
                    (height - 48).max(50),
                    hwnd,
                    ptr::null_mut(),
                    hinstance,
                    ptr::null(),
                );
                let filler = CreateWindowExW(
                    0,
                    details_ptr,
                    ptr::null(),
                    WS_CHILD | WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                    218,
                    5,
                    (width - 223).max(50),
                    (height - 12).max(50),
                    hwnd,
                    ptr::null_mut(),
                    hinstance,
                    ptr::null(),
                );
                (details, filler)
            });

        let lbl_filler = with_wide_null("STATIC", |static_ptr| {
            with_wide_null(
                "No tunnels configured.\nImport an existing tunnel configuration to connect.",
                |text_ptr| unsafe {
                    CreateWindowExW(
                        0,
                        static_ptr,
                        text_ptr,
                        WS_CHILD | WS_VISIBLE,
                        20,
                        60,
                        350,
                        60,
                        filler_container,
                        ptr::null_mut(),
                        hinstance,
                        ptr::null(),
                    )
                },
            )
        });

        let btn_filler_import = with_wide_null("BUTTON", |btn_ptr| {
            with_wide_null("&Import tunnel(s) from file…", |text_ptr| unsafe {
                CreateWindowExW(
                    0,
                    btn_ptr,
                    text_ptr,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                    20,
                    140,
                    220,
                    36,
                    filler_container,
                    ID_BTN_FILLER_IMPORT as *mut _,
                    hinstance,
                    ptr::null(),
                )
            })
        });

        // Apply Segoe UI font to all child controls
        for ctrl in [
            btn_add,
            btn_import,
            btn_toggle,
            btn_edit,
            btn_delete,
            lbl_filler,
            btn_filler_import,
        ] {
            if !ctrl.is_null() && !font.is_null() {
                unsafe {
                    SendMessageW(ctrl, WM_SETFONT, font as WPARAM, 1 as LPARAM);
                }
            }
        }

        let mut inner = Box::new(TunnelsPageInner {
            hwnd,
            list_view,
            btn_add,
            btn_import,
            details_container,
            btn_toggle,
            btn_edit,
            btn_delete,
            filler_container,
            _lbl_filler: lbl_filler,
            _btn_filler_import: btn_filler_import,
            font,
            font_bold,
            font_large,
            is_active: false,
            selected_state: TunnelState::Stopped,
            visible: true,
            details_dirty: true,
            paint_dirty: false,
            showing_filler: None,
            rendered_tunnel_name: None,
            current_config: None,
            rendered_details: RenderedDetailsCache::default(),
            config_cache: HashMap::with_capacity(16),
            pending_ops: HashSet::new(),
            scm: ScmHandle::open(SC_MANAGER_CONNECT).ok(),
            width,
            height,
            in_batch_update: false,
        });

        // Link instance to HWND USERDATA (including filler_container so its button forwards WM_COMMAND!)
        let raw_ptr: *mut TunnelsPageInner = &mut *inner;
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, raw_ptr as isize);
            SetWindowLongPtrW(details_container, GWLP_USERDATA, raw_ptr as isize);
            SetWindowLongPtrW(filler_container, GWLP_USERDATA, raw_ptr as isize);
        }

        // Perform initial layout & fast non-blocking tunnel enumeration; autostart launches asynchronously
        log_to_file("TunnelsPage::new(): calling layout...");
        inner.layout(width, height);
        log_to_file("TunnelsPage::new(): calling refresh_tunnels...");
        let _ = inner.refresh_tunnels();
        inner.spawn_autostart_startup();
        log_to_file("TunnelsPage::new(): refresh_tunnels done");

        Ok(Self { inner })
    }

    /// Returns the Win32 window handle `HWND` of this container.
    pub fn hwnd(&self) -> HWND {
        self.inner.hwnd
    }

    /// Resizes the container window and updates child layout.
    pub fn resize(&mut self, rect: RECT) {
        self.inner.resize(rect);
    }

    /// Refreshes the list of tunnels from the local configuration store.
    pub fn refresh_tunnels(&mut self) -> Result<()> {
        self.inner.refresh_tunnels()
    }

    /// Called when the `Configurations` directory changes on disk.
    pub fn on_configs_changed(&mut self) {
        self.inner.on_configs_changed();
    }

    /// Called when SCM reports a tunnel service state or registration change.
    pub fn on_service_state_changed(&mut self) {
        self.inner.poll_service_states();
    }

    /// Called when page / window visibility changes (tab switch, show, or minimize-to-tray).
    pub fn on_visibility_changed(&mut self, visible: bool) {
        self.inner.on_visibility_changed(visible);
    }

    /// Returns the currently selected tunnel name, or `None` if no tunnel is selected.
    pub fn selected_tunnel(&self) -> Option<String> {
        self.inner.selected_tunnel()
    }

    /// Sets the active toggle state for the selected tunnel.
    pub fn set_active_state(&mut self, active: bool) {
        self.inner.set_active_state(active);
    }

    /// Polls live service states for all listed tunnels without full rebuilds.
    pub fn poll_service_states(&mut self) {
        self.inner.poll_service_states();
    }

    /// Returns a slice of the listed tunnels and their current states.
    pub fn tunnels(&self) -> &[TunnelItem] {
        self.inner.list_view.tunnels()
    }

    /// Toggles a specific tunnel by name (used by the system tray context menu).
    pub fn toggle_tunnel_by_name(&mut self, name: &str) {
        self.inner.list_view.select_tunnel(name);
        self.inner.update_selection_state();
        self.inner.on_toggle_tunnel();
    }

    /// Opens the import tunnel dialog.
    pub fn trigger_import_tunnel(&mut self) {
        self.inner.on_import_tunnel();
    }
}

/// Queries the current Windows Service state given a NUL-terminated UTF-16 service name pointer.
fn query_tunnel_service_state_ptr(
    scm: Option<&ScmHandle>,
    svc_name_ptr: *const u16,
) -> TunnelState {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenServiceW, QueryServiceStatus, SERVICE_STATUS,
    };

    let check_raw = |scm_raw: *mut core::ffi::c_void| -> TunnelState {
        unsafe {
            let h_svc = OpenServiceW(scm_raw, svc_name_ptr, SERVICE_QUERY_STATUS);
            if h_svc.is_null() {
                return TunnelState::Stopped;
            }
            let mut st: SERVICE_STATUS = std::mem::zeroed();
            let ok = QueryServiceStatus(h_svc, &mut st);
            CloseServiceHandle(h_svc);
            if ok != 0 {
                match st.dwCurrentState {
                    SERVICE_RUNNING => TunnelState::Started,
                    SERVICE_START_PENDING => TunnelState::Starting,
                    SERVICE_STOP_PENDING => TunnelState::Stopping,
                    _ => TunnelState::Stopped,
                }
            } else {
                TunnelState::Stopped
            }
        }
    };

    if let Some(s) = scm {
        check_raw(s.as_raw())
    } else if let Ok(s) = ScmHandle::open(SC_MANAGER_CONNECT) {
        check_raw(s.as_raw())
    } else {
        TunnelState::Stopped
    }
}

/// Queries the current Windows Service state using a pre-encoded UTF-16 service name
/// with zero heap allocations.
fn query_tunnel_service_state_wide(scm: Option<&ScmHandle>, svc_name_wide: &[u16]) -> TunnelState {
    query_tunnel_service_state_ptr(scm, svc_name_wide.as_ptr())
}

/// Queries the current Windows Service state for `WireGuardTunnel$<name>` using a stack buffer.
fn query_tunnel_service_state(scm: Option<&ScmHandle>, name: &str) -> TunnelState {
    with_tunnel_service_name_wide(name, |ptr| query_tunnel_service_state_ptr(scm, ptr))
}

impl TunnelsPageInner {
    pub fn resize(&mut self, rect: RECT) {
        let width = (rect.right - rect.left).max(0);
        let height = (rect.bottom - rect.top).max(0);
        self.width = width;
        self.height = height;

        unsafe {
            MoveWindow(self.hwnd, rect.left, rect.top, width, height, TRUE);
        }

        self.layout(width, height);
    }

    fn invalidate_details(&mut self) {
        if self.visible {
            self.paint_dirty = false;
            unsafe {
                InvalidateRect(self.details_container, ptr::null(), FALSE);
            }
        } else {
            self.paint_dirty = true;
        }
    }

    pub fn on_configs_changed(&mut self) {
        self.config_cache.clear();
        self.details_dirty = true;
        let _ = self.refresh_tunnels();
        post_tray_sync(self.hwnd);
    }

    pub fn on_visibility_changed(&mut self, visible: bool) {
        self.visible = visible;
        if visible {
            self.poll_service_states();
            if self.details_dirty {
                self.update_selection_state();
            } else if self.paint_dirty {
                self.invalidate_details();
            }
        }
    }

    pub fn poll_service_states(&mut self) {
        if self.scm.is_none() {
            self.scm = ScmHandle::open(SC_MANAGER_CONNECT).ok();
        }
        let selected_idx = self.list_view.selected_index();
        let mut selected_state_changed = false;
        let mut any_changed = false;
        let mut new_selected_state = TunnelState::Stopped;

        let len = self.list_view.tunnel_count();
        for idx in 0..len {
            let (live_state, old_state) = {
                let item = &self.list_view.tunnels()[idx];
                let live_state =
                    query_tunnel_service_state_wide(self.scm.as_ref(), &item.svc_name_wide);
                if self.pending_ops.contains(&item.name) {
                    let keep_optimistic = (item.state == TunnelState::Starting
                        && live_state == TunnelState::Stopped)
                        || (item.state == TunnelState::Stopping
                            && (live_state == TunnelState::Started
                                || live_state == TunnelState::Starting));
                    if keep_optimistic {
                        continue;
                    }
                }
                (live_state, item.state)
            };
            if live_state != old_state {
                self.list_view.update_tunnel_state_at(idx, live_state);
                any_changed = true;
                if selected_idx == Some(idx) {
                    selected_state_changed = true;
                    new_selected_state = live_state;
                }
            }
        }

        if selected_state_changed {
            let active = new_selected_state == TunnelState::Started
                || new_selected_state == TunnelState::Starting;
            let active_changed = self.is_active != active;
            self.is_active = active;
            self.selected_state = new_selected_state;
            if active_changed {
                let labels = details_labels();
                let label_ptr = if active {
                    labels.btn_deactivate.as_ptr()
                } else {
                    labels.btn_activate.as_ptr()
                };
                unsafe {
                    SetWindowTextW(self.btn_toggle, label_ptr);
                }
            }
            self.invalidate_details();
        }

        if any_changed {
            post_tray_sync(self.hwnd);
        }
    }

    fn spawn_autostart_startup(&self) {
        let target_hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let mut any_started = false;
            if let Ok(autostarts) = wireguard_manager::autostart::get_autostart_tunnels() {
                if !autostarts.is_empty() {
                    if let Ok(scm) = ScmHandle::open(SC_MANAGER_ALL_ACCESS) {
                        for auto_tunnel in &autostarts {
                            let cur_state = query_tunnel_service_state(Some(&scm), auto_tunnel);
                            if cur_state == TunnelState::Stopped {
                                if let Ok(svc_name) = service_name_of_tunnel(auto_tunnel) {
                                    if let Ok(svc) = scm.open_service(&svc_name, SERVICE_ALL_ACCESS)
                                    {
                                        if svc.start_service(&[]).is_ok() {
                                            any_started = true;
                                            log_to_file(&format!(
                                                "TunnelsPageInner: started autostart tunnel service '{svc_name}'"
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            post_tunnel_op_result(target_hwnd, TunnelOpResult::AutostartSynced { any_started });
        });
    }

    pub fn refresh_tunnels(&mut self) -> Result<()> {
        log_to_file("TunnelsPageInner::refresh_tunnels(): starting");
        if self.scm.is_none() {
            self.scm = ScmHandle::open(SC_MANAGER_CONNECT).ok();
        }

        let mut items = Vec::new();
        let config_dirs = [
            PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations"),
            PathBuf::from(r"C:\ProgramData\WireGuard\Configurations"),
        ];

        for dir in &config_dirs {
            if dir.is_dir() {
                if let Ok(names) = list_config_names(dir) {
                    items.reserve(names.len());
                    for name in names {
                        let st = if self.pending_ops.contains(&name) {
                            self.list_view
                                .tunnels()
                                .iter()
                                .find(|t| t.name == name)
                                .map(|t| t.state)
                                .unwrap_or_else(|| {
                                    query_tunnel_service_state(self.scm.as_ref(), &name)
                                })
                        } else {
                            query_tunnel_service_state(self.scm.as_ref(), &name)
                        };
                        items.push(TunnelItem::new(name, st));
                    }
                    break;
                }
            }
        }

        let count = items.len();
        log_to_file(&format!("TunnelsPageInner::refresh_tunnels(): found {count} tunnels"));

        self.in_batch_update = true;
        self.list_view.set_tunnels(items);
        self.in_batch_update = false;

        // Purge deleted tunnels from config_cache so closed/removed tunnels do not leak RAM
        let tunnels = self.list_view.tunnels();
        let old_cache_len = self.config_cache.len();
        self.config_cache
            .retain(|name, _| tunnels.iter().any(|t| &t.name == name));
        if self.config_cache.len() != old_cache_len {
            self.details_dirty = true;
        }
        if let Some(ref rendered) = self.rendered_tunnel_name {
            if !tunnels.iter().any(|t| &t.name == rendered) {
                self.details_dirty = true;
            }
        }

        let need_filler = count == 0;
        if self.showing_filler != Some(need_filler) {
            self.showing_filler = Some(need_filler);
            unsafe {
                if !need_filler {
                    ShowWindow(self.filler_container, SW_HIDE);
                    ShowWindow(self.details_container, SW_SHOW);
                    ShowWindow(self.btn_toggle, SW_SHOW);
                    ShowWindow(self.btn_edit, SW_SHOW);
                    ShowWindow(self.btn_delete, SW_SHOW);
                } else {
                    ShowWindow(self.filler_container, SW_SHOW);
                    ShowWindow(self.details_container, SW_HIDE);
                    ShowWindow(self.btn_toggle, SW_HIDE);
                    ShowWindow(self.btn_edit, SW_HIDE);
                    ShowWindow(self.btn_delete, SW_HIDE);
                }
            }
        }

        self.update_selection_state();
        log_to_file("TunnelsPageInner::refresh_tunnels(): finished successfully");
        Ok(())
    }

    pub fn selected_tunnel(&self) -> Option<String> {
        self.list_view.selected_tunnel()
    }

    pub fn set_active_state(&mut self, active: bool) {
        let active_changed = self.is_active != active;
        let state = if active {
            TunnelState::Started
        } else {
            TunnelState::Stopped
        };
        let state_changed_local = self.selected_state != state;
        self.is_active = active;
        self.selected_state = state;
        let labels = details_labels();
        let label_ptr = if active {
            labels.btn_deactivate.as_ptr()
        } else {
            labels.btn_activate.as_ptr()
        };

        let selected = self.list_view.selected_tunnel();
        let can_enable = selected
            .as_ref()
            .is_some_and(|n| !self.pending_ops.contains(n));

        unsafe {
            SetWindowTextW(self.btn_toggle, label_ptr);
            EnableWindow(self.btn_toggle, if can_enable { TRUE } else { FALSE });
        }

        if let Some(ref name) = selected {
            let state_changed = self.list_view.update_tunnel_state(name, state);
            if active_changed || state_changed_local || state_changed {
                self.invalidate_details();
                post_tray_sync(self.hwnd);
            }
        }
    }

    fn layout(&mut self, width: i32, height: i32) {
        const LEFT_WIDTH: i32 = 210;
        const MARGIN: i32 = 5;
        const BTN_H: i32 = 28;

        // 1. Left pane: List View
        let lv_height = (height - MARGIN * 2 - BTN_H - 4).max(50);
        self.list_view.resize(MARGIN, MARGIN, LEFT_WIDTH - MARGIN, lv_height);

        // 2. Left pane: Buttons below list
        let btn_y = height - MARGIN - BTN_H;
        let btn_half = (LEFT_WIDTH - MARGIN - 4) / 2;
        unsafe {
            SetWindowPos(
                self.btn_add,
                ptr::null_mut(),
                MARGIN,
                btn_y,
                btn_half,
                BTN_H,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            SetWindowPos(
                self.btn_import,
                ptr::null_mut(),
                MARGIN + btn_half + 4,
                btn_y,
                btn_half,
                BTN_H,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }

        // 3. Right pane: Details Container & Filler Container
        let right_x = LEFT_WIDTH + 8;
        let right_width = (width - right_x - MARGIN).max(50);
        let details_height = (height - MARGIN - 42).max(50);

        unsafe {
            SetWindowPos(
                self.details_container,
                ptr::null_mut(),
                right_x,
                MARGIN,
                right_width,
                details_height,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            SetWindowPos(
                self.filler_container,
                ptr::null_mut(),
                right_x,
                MARGIN,
                right_width,
                (height - MARGIN * 2).max(50),
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }

        // 4. Right pane: Action buttons bar
        let action_y = height - MARGIN - 32;
        unsafe {
            SetWindowPos(
                self.btn_toggle,
                ptr::null_mut(),
                right_x,
                action_y,
                110,
                30,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            SetWindowPos(
                self.btn_edit,
                ptr::null_mut(),
                right_x + 118,
                action_y,
                80,
                30,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            SetWindowPos(
                self.btn_delete,
                ptr::null_mut(),
                right_x + 206,
                action_y,
                80,
                30,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }

    fn update_selection_state(&mut self) {
        let selected = self.list_view.selected_tunnel();
        let has_selection = selected.is_some();
        let is_pending = selected
            .as_ref()
            .is_some_and(|n| self.pending_ops.contains(n));

        unsafe {
            EnableWindow(
                self.btn_toggle,
                if has_selection && !is_pending { TRUE } else { FALSE },
            );
            EnableWindow(
                self.btn_edit,
                if has_selection && !is_pending { TRUE } else { FALSE },
            );
            EnableWindow(
                self.btn_delete,
                if has_selection && !is_pending { TRUE } else { FALSE },
            );
        }

        if let Some(ref name) = selected {
            let state = self
                .list_view
                .tunnels()
                .iter()
                .find(|t| &t.name == name)
                .map(|t| t.state)
                .unwrap_or(TunnelState::Stopped);

            let new_active = state == TunnelState::Started || state == TunnelState::Starting;
            let active_changed = self.is_active != new_active;
            let state_changed = self.selected_state != state;
            let need_rebuild =
                self.details_dirty || self.rendered_tunnel_name.as_deref() != Some(name.as_str());

            self.is_active = new_active;
            self.selected_state = state;

            if active_changed || need_rebuild {
                let labels = details_labels();
                let label_ptr = if new_active {
                    labels.btn_deactivate.as_ptr()
                } else {
                    labels.btn_activate.as_ptr()
                };
                unsafe {
                    SetWindowTextW(self.btn_toggle, label_ptr);
                }
            }

            if need_rebuild {
                self.current_config = self.get_or_load_tunnel_config(name);
                self.rebuild_rendered_details(name);
                self.rendered_tunnel_name = Some(name.clone());
                self.details_dirty = false;
                self.invalidate_details();
            } else if active_changed || state_changed {
                self.invalidate_details();
            }
        } else {
            let was_non_empty =
                self.rendered_tunnel_name.is_some() || !self.rendered_details.title.is_empty();
            self.is_active = false;
            self.selected_state = TunnelState::Stopped;
            self.current_config = None;
            self.rendered_tunnel_name = None;
            self.details_dirty = false;
            if was_non_empty {
                self.rendered_details.title.clear();
                self.rendered_details.interface_fields.clear();
                self.rendered_details.peers.clear();
                self.invalidate_details();
            }
        }
    }

    fn rebuild_rendered_details(&mut self, tunnel_name: &str) {
        use std::fmt::Write;

        let labels = details_labels();
        let mut scratch = String::with_capacity(64);
        let mut b64_buf = [0u8; 44];

        let _ = write!(&mut scratch, "Interface: {tunnel_name}");
        self.rendered_details.title = to_wide_null(&scratch);
        self.rendered_details.interface_fields.clear();
        self.rendered_details.peers.clear();

        if let Some(ref config) = self.current_config {
            if let Some(ref priv_key) = config.interface.private_key {
                let pub_b64 = priv_key.public_key().encode_base64(&mut b64_buf);
                self.rendered_details.interface_fields.push(RenderedField {
                    label: labels.pubkey.as_slice(),
                    value: to_wide_null(pub_b64),
                });
            }
            if !config.interface.addresses.is_empty() {
                scratch.clear();
                for (i, a) in config.interface.addresses.iter().enumerate() {
                    if i > 0 {
                        scratch.push_str(", ");
                    }
                    let _ = write!(&mut scratch, "{a}");
                }
                self.rendered_details.interface_fields.push(RenderedField {
                    label: labels.addresses.as_slice(),
                    value: to_wide_null(&scratch),
                });
            }
            if let Some(port) = config.interface.listen_port {
                scratch.clear();
                let _ = write!(&mut scratch, "{port}");
                self.rendered_details.interface_fields.push(RenderedField {
                    label: labels.listen_port.as_slice(),
                    value: to_wide_null(&scratch),
                });
            }
            if !config.interface.dns.is_empty() {
                scratch.clear();
                for (i, d) in config.interface.dns.iter().enumerate() {
                    if i > 0 {
                        scratch.push_str(", ");
                    }
                    let _ = write!(&mut scratch, "{d}");
                }
                self.rendered_details.interface_fields.push(RenderedField {
                    label: labels.dns.as_slice(),
                    value: to_wide_null(&scratch),
                });
            }
            if let Some(mtu) = config.interface.mtu {
                scratch.clear();
                let _ = write!(&mut scratch, "{mtu}");
                self.rendered_details.interface_fields.push(RenderedField {
                    label: labels.mtu.as_slice(),
                    value: to_wide_null(&scratch),
                });
            }

            for (i, peer) in config.peers.iter().enumerate() {
                let mut fields = Vec::with_capacity(3);
                let peer_b64 = peer.public_key.encode_base64(&mut b64_buf);
                fields.push(RenderedField {
                    label: labels.pubkey.as_slice(),
                    value: to_wide_null(peer_b64),
                });
                if let Some(ref ep) = peer.endpoint {
                    scratch.clear();
                    let _ = write!(&mut scratch, "{ep}");
                    fields.push(RenderedField {
                        label: labels.endpoint.as_slice(),
                        value: to_wide_null(&scratch),
                    });
                }
                if !peer.allowed_ips.is_empty() {
                    scratch.clear();
                    for (j, ip) in peer.allowed_ips.iter().enumerate() {
                        if j > 0 {
                            scratch.push_str(", ");
                        }
                        let _ = write!(&mut scratch, "{ip}");
                    }
                    fields.push(RenderedField {
                        label: labels.allowed_ips.as_slice(),
                        value: to_wide_null(&scratch),
                    });
                }
                scratch.clear();
                let _ = write!(&mut scratch, "Peer {}", i + 1);
                self.rendered_details.peers.push(RenderedPeer {
                    title: to_wide_null(&scratch),
                    fields,
                });
            }
        }
    }

    fn get_or_load_tunnel_config(&mut self, name: &str) -> Option<TunnelConfig> {
        if let Some(cached) = self.config_cache.get(name) {
            return Some(cached.clone());
        }
        if let Some(loaded) = Self::fetch_tunnel_config(name) {
            self.config_cache.insert(name.to_string(), loaded.clone());
            return Some(loaded);
        }
        None
    }

    fn fetch_tunnel_config(name: &str) -> Option<TunnelConfig> {
        // 1. Decrypt DPAPI or load from ConfigDir under LocalSystem impersonation
        let name_owned = name.to_string();
        match wireguard_elevate::do_as_system(move || {
            let dpapi_path = format!(
                r"C:\Program Files\WireGuard\Data\Configurations\{name_owned}.conf.dpapi"
            );
            if let Ok(bytes) = std::fs::read(&dpapi_path) {
                let dec_res =
                    wireguard_dpapi::decrypt_with_expected_description(&bytes, &name_owned)
                        .or_else(|_| wireguard_dpapi::decrypt(&bytes));
                match dec_res {
                    Ok(dec) => match parse_config_bytes(&dec, &name_owned) {
                        Ok(cfg) => return Ok(Some(cfg)),
                        Err(e) => {
                            log_to_file(&format!(
                                "fetch_tunnel_config({}): parse_config_bytes failed: {}",
                                name_owned, e
                            ));
                        }
                    },
                    Err(e) => {
                        log_to_file(&format!(
                            "fetch_tunnel_config({}): DPAPI decrypt failed: {}",
                            name_owned, e
                        ));
                    }
                }
            }
            if let Ok(dir) = ConfigDir::open_default() {
                if let Ok(cfg) = dir.load_config(&name_owned) {
                    return Ok(Some(cfg));
                }
            }
            Ok(None)
        }) {
            Ok(Some(cfg)) => {
                log_to_file(&format!(
                    "fetch_tunnel_config({}): successfully decrypted config ({} peers)",
                    name,
                    cfg.peers.len()
                ));
                return Some(cfg);
            }
            Ok(None) => {
                log_to_file(&format!("fetch_tunnel_config({}): returned None", name));
            }
            Err(e) => {
                log_to_file(&format!("fetch_tunnel_config({}): do_as_system error: {}", name, e));
            }
        }

        // 2. Direct fallback for unencrypted `.conf` files
        let possible_paths = [
            format!(r"C:\Program Files\WireGuard\Data\Configurations\{name}.conf"),
            format!(r"C:\ProgramData\WireGuard\Configurations\{name}.conf"),
        ];

        for path in &possible_paths {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(cfg) = parse_config_bytes(&bytes, name) {
                    return Some(cfg);
                }
            }
        }

        None
    }

    fn on_add_tunnel_menu(&mut self) {
        let mut rc: RECT = unsafe { std::mem::zeroed() };
        let cmd = unsafe {
            GetClientRect(self.btn_add, &mut rc);
            let mut pt = POINT {
                x: rc.left,
                y: rc.bottom,
            };
            windows_sys::Win32::Graphics::Gdi::ClientToScreen(self.btn_add, &mut pt);

            let hmenu = CreatePopupMenu();
            with_wide_null("&Import tunnel(s) from file…\tCtrl+O", |import_ptr| {
                AppendMenuW(hmenu, MF_STRING, ID_MENU_IMPORT, import_ptr);
            });
            with_wide_null("&Add empty tunnel…\tCtrl+N", |add_ptr| {
                AppendMenuW(hmenu, MF_STRING, ID_MENU_ADD_EMPTY, add_ptr);
            });

            let cmd = TrackPopupMenu(
                hmenu,
                TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
                pt.x,
                pt.y,
                0,
                self.hwnd,
                ptr::null(),
            );
            DestroyMenu(hmenu);
            cmd
        };

        if cmd as usize == ID_MENU_IMPORT {
            self.on_import_tunnel();
        } else if cmd as usize == ID_MENU_ADD_EMPTY {
            self.on_add_empty_tunnel();
        }
    }

    fn on_import_tunnel(&mut self) {
        let selected_files = crate::filesave::select_import_config_files(self.hwnd);
        if selected_files.is_empty() {
            return;
        }

        let target_hwnd = self.hwnd as isize;
        std::thread::spawn(move || {
            let mut configs = Vec::new();
            let mut errors = Vec::new();

            for path in selected_files {
                match crate::filesave::collect_import_configs(&path) {
                    Ok(mut parsed) => configs.append(&mut parsed),
                    Err(e) => errors.push(format!("{}: {e}", path.display())),
                }
            }

            post_tunnel_op_result(target_hwnd, TunnelOpResult::ImportParsed { configs, errors });
        });
    }

    fn on_add_empty_tunnel(&mut self) {
        if let Some(new_cfg) = crate::editdialog::run_edit_dialog(self.hwnd, None) {
            let name = new_cfg.name.clone();
            log_to_file(&format!("Created new tunnel '{name}'"));
            self.config_cache.insert(name.clone(), new_cfg);
            self.details_dirty = true;
            let _ = self.refresh_tunnels();
            self.list_view.select_tunnel(&name);
            self.update_selection_state();
            post_tray_sync(self.hwnd);
        }
    }

    fn on_toggle_tunnel(&mut self) {
        let (tunnel_name, is_currently_active) = match self.list_view.selected_tunnel() {
            Some(name) => (name, self.is_active),
            None => return,
        };
        if self.pending_ops.contains(&tunnel_name) {
            return;
        }

        let svc_name = match service_name_of_tunnel(&tunnel_name) {
            Ok(s) => s,
            Err(e) => {
                log_to_file(&format!("Invalid tunnel name '{}': {}", tunnel_name, e));
                return;
            }
        };

        self.pending_ops.insert(tunnel_name.clone());
        let target_hwnd = self.hwnd as isize;

        if is_currently_active {
            log_to_file(&format!(
                "Deactivating tunnel '{}' (service '{}')...",
                tunnel_name, svc_name
            ));
            self.list_view
                .update_tunnel_state(&tunnel_name, TunnelState::Stopping);
            self.update_selection_state();

            let other_active = self.list_view.tunnels().iter().any(|t| {
                t.name != tunnel_name
                    && (t.state == TunnelState::Started || t.state == TunnelState::Starting)
            });

            std::thread::spawn(move || {
                if let Ok(scm) = ScmHandle::open(SC_MANAGER_ALL_ACCESS) {
                    if let Ok(svc) = scm.open_service(&svc_name, SERVICE_ALL_ACCESS) {
                        // Set start type to DEMAND_START (0x00000003) and stop the service in-place
                        // instead of deleting it, avoiding Win32 error 1072 (ERROR_SERVICE_MARKED_FOR_DELETE).
                        let _ = svc.set_start_type(0x00000003 /* SERVICE_DEMAND_START */);
                        let _ = svc.stop_service();
                    }
                } else if !wireguard_elevate::is_current_process_elevated() {
                    if let Ok(exe) = std::env::current_exe() {
                        let args = format!("/uninstalltunnelservice \"{tunnel_name}\"");
                        if wireguard_elevate::shell_execute_runas(
                            &exe.to_string_lossy(),
                            &args,
                            None,
                            SW_HIDE as i32,
                        )
                        .is_ok()
                        {
                            let _ = wireguard_service::wait_service_status_change(
                                &svc_name,
                                SERVICE_NOTIFY_STOPPED,
                                None,
                                Some(2_000),
                            );
                        }
                    }
                }

                let st = query_tunnel_service_state(None, &tunnel_name);
                let still_active = st == TunnelState::Started || st == TunnelState::Starting;

                if !still_active {
                    let _ = wireguard_manager::autostart::remove_autostart_tunnel(&tunnel_name);
                    log_to_file(&format!("Tunnel '{}' deactivated", tunnel_name));
                }

                let name_for_task = tunnel_name.clone();
                post_tunnel_op_result(
                    target_hwnd,
                    TunnelOpResult::Deactivated {
                        tunnel_name,
                        still_active,
                    },
                );

                if !still_active && !other_active {
                    let _ = wireguard_manager::autostart::set_windows_logon_autostart(false);
                    log_to_file(&format!(
                        "All tunnels inactive after '{}': Windows logon auto-start disabled",
                        name_for_task
                    ));
                }
            });
        } else {
            log_to_file(&format!(
                "Activating tunnel '{}' (service '{}')...",
                tunnel_name, svc_name
            ));
            self.list_view
                .update_tunnel_state(&tunnel_name, TunnelState::Starting);
            self.update_selection_state();

            let cached_cfg = self.config_cache.get(&tunnel_name).cloned();

            std::thread::spawn(move || {
                let conf_dir = ConfigDir::resolve_data_directory(false)
                    .map(|root| root.join("Configurations"))
                    .unwrap_or_else(|_| {
                        PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations")
                    });
                let dpapi_path = conf_dir.join(format!("{tunnel_name}.conf.dpapi"));
                let conf_path = conf_dir.join(format!("{tunnel_name}.conf"));

                let config_arg = if dpapi_path.exists() {
                    dpapi_path.to_string_lossy().into_owned()
                } else {
                    let cfg_opt = cached_cfg.or_else(|| {
                        ConfigDir::open_default()
                            .ok()
                            .and_then(|dir| dir.load_config(&tunnel_name).ok())
                    });
                    if let Some(cfg) = cfg_opt {
                        if let Ok(Some(saved_path)) = wireguard_elevate::do_as_system(move || {
                            if let Ok(dir) = ConfigDir::open_default() {
                                if let Ok(p) = dir.save_config(&cfg, true) {
                                    return Ok(Some(p.to_string_lossy().into_owned()));
                                }
                            }
                            Ok(None)
                        }) {
                            saved_path
                        } else {
                            conf_path.to_string_lossy().into_owned()
                        }
                    } else {
                        dpapi_path.to_string_lossy().into_owned()
                    }
                };

                let exe_str = wireguard_manager::autostart::get_wireguard_exe_path()
                    .to_string_lossy()
                    .into_owned();
                let bin_path = format!("\"{exe_str}\" /tunnelservice \"{config_arg}\"");
                let display_name = format!("WireGuard Tunnel: {tunnel_name}");

                let mut start_err: Option<String> = None;
                let scm_res = ScmHandle::open(SC_MANAGER_ALL_ACCESS).or_else(|e| {
                    // If the current process was started without elevation, elevate via `/installtunnelservice`
                    if !wireguard_elevate::is_current_process_elevated() {
                        let args = format!("/installtunnelservice \"{config_arg}\"");
                        if wireguard_elevate::shell_execute_runas(
                            &exe_str,
                            &args,
                            None,
                            SW_HIDE as i32,
                        )
                        .is_ok()
                        {
                            let _ = wireguard_service::wait_service_status_change(
                                &svc_name,
                                SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_START_PENDING,
                                None,
                                Some(2_000),
                            );
                        }
                    }
                    Err(e)
                });

                match scm_res {
                    Ok(scm) => {
                        // Reuse existing tunnel service in-place via update_config(SERVICE_AUTO_START)
                        // or create a new one if it doesn't exist. If an old handle marked the service
                        // for deletion (Win32 error 1072), wait briefly for SCM to purge it and retry.
                        let create_with_retry = || {
                            for attempt in 0..25 {
                                match scm.create_service(
                                    &svc_name,
                                    &display_name,
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS,
                                    SERVICE_AUTO_START,
                                    SERVICE_ERROR_NORMAL,
                                    &bin_path,
                                    None,
                                    Some(&["Nsi", "TcpIp"]),
                                    None,
                                    None,
                                ) {
                                    Ok(s) => return Ok(s),
                                    Err(wireguard_service::ServiceError::CreateService {
                                        code: 1072, // ERROR_SERVICE_MARKED_FOR_DELETE
                                        ..
                                    }) if attempt < 24 => {
                                        std::thread::sleep(std::time::Duration::from_millis(120));
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                            unreachable!()
                        };

                        let svc_res = match scm.open_service(&svc_name, SERVICE_ALL_ACCESS) {
                            Ok(existing) => {
                                match existing.update_config(
                                    SERVICE_AUTO_START,
                                    Some(&bin_path),
                                    Some(&display_name),
                                ) {
                                    Ok(()) => Ok(existing),
                                    Err(wireguard_service::ServiceError::ConfigureService {
                                        code: 1072, // ERROR_SERVICE_MARKED_FOR_DELETE
                                        ..
                                    }) => {
                                        drop(existing);
                                        create_with_retry()
                                    }
                                    Err(_) => Ok(existing),
                                }
                            }
                            Err(_) => create_with_retry(),
                        };

                        match svc_res {
                            Ok(svc) => {
                                // Grant unrestricted service SID so tunnel service can manage WFP/IPCfg
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

                                if let Ok(st) = svc.query_status() {
                                    if st.dwCurrentState == SERVICE_STOP_PENDING {
                                        let _ = wireguard_service::wait_service_status_change(
                                            &svc_name,
                                            SERVICE_NOTIFY_STOPPED,
                                            None,
                                            Some(5_000),
                                        );
                                    }
                                }

                                match svc.start_service(&[]) {
                                    Ok(()) => {
                                        log_to_file(&format!(
                                            "Tunnel service '{}' started successfully",
                                            svc_name
                                        ));
                                    }
                                    Err(wireguard_service::ServiceError::StartService {
                                        code: 1056, // ERROR_SERVICE_ALREADY_RUNNING
                                        ..
                                    }) => {
                                        log_to_file(&format!(
                                            "Tunnel service '{}' is already running",
                                            svc_name
                                        ));
                                    }
                                    Err(e) => {
                                        start_err = Some(e.to_string());
                                    }
                                }
                            }
                            Err(e) => {
                                start_err = Some(e.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        let st = query_tunnel_service_state(None, &tunnel_name);
                        if st != TunnelState::Started && st != TunnelState::Starting {
                            start_err = Some(e.to_string());
                        }
                    }
                }

                if start_err.is_none() {
                    let _ = wireguard_manager::autostart::add_autostart_tunnel(&tunnel_name);
                }

                let ok = start_err.is_none();
                let name_for_task = tunnel_name.clone();
                post_tunnel_op_result(
                    target_hwnd,
                    TunnelOpResult::Activated {
                        tunnel_name,
                        error: start_err,
                    },
                );

                if ok {
                    let _ = wireguard_manager::autostart::set_windows_logon_autostart(true);
                    log_to_file(&format!(
                        "Tunnel '{}' activated: Windows logon auto-start enabled",
                        name_for_task
                    ));

                    // If the service is still in SERVICE_START_PENDING, wait event-driven for
                    // SERVICE_RUNNING/SERVICE_STOPPED and immediately notify the UI so it never
                    // stalls on "Activating..." even if SCM DB creation watcher lagged.
                    if query_tunnel_service_state(None, &name_for_task) == TunnelState::Starting {
                        let _ = wireguard_service::wait_service_status_change(
                            &svc_name,
                            SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED,
                            None,
                            Some(15_000),
                        );
                        unsafe {
                            let _ = PostMessageW(
                                target_hwnd as HWND,
                                WM_APP_SERVICE_STATE_CHANGED,
                                0,
                                0,
                            );
                        }
                    }
                }
            });
        }
    }

    fn on_edit_tunnel(&mut self) {
        let name = match self.selected_tunnel() {
            Some(n) => n,
            None => return,
        };
        if self.pending_ops.contains(&name) {
            return;
        }

        let existing = self.get_or_load_tunnel_config(&name);
        if let Some(updated_cfg) = crate::editdialog::run_edit_dialog(self.hwnd, existing.as_ref()) {
            let new_name = updated_cfg.name.clone();
            if new_name != name {
                // Tunnel was renamed; remove old config file
                let old_name = name.clone();
                let _ = wireguard_elevate::do_as_system(move || {
                    if let Ok(dir) = ConfigDir::open_default() {
                        let _ = dir.delete_config(&old_name);
                    }
                    Ok(())
                });
                self.config_cache.remove(&name);
            }
            self.config_cache.insert(new_name.clone(), updated_cfg);
            self.details_dirty = true;
            let _ = self.refresh_tunnels();
            self.list_view.select_tunnel(&new_name);
            self.update_selection_state();
            post_tray_sync(self.hwnd);
            log_to_file(&format!("Edited tunnel '{new_name}'"));
        }
    }

    fn on_delete_tunnel(&mut self) {
        let (parent_hwnd, name) = match self.list_view.selected_tunnel() {
            Some(n) => (self.hwnd, n),
            None => return,
        };
        if self.pending_ops.contains(&name) {
            return;
        }

        let title = format!("Delete tunnel ‘{name}’");
        let question = format!(
            "Are you sure you would like to delete tunnel ‘{name}’? You cannot undo this action."
        );
        if !confirm_warning_yes_no(parent_hwnd, &title, &question) || self.pending_ops.contains(&name)
        {
            return;
        }

        self.pending_ops.insert(name.clone());
        self.list_view
            .update_tunnel_state(&name, TunnelState::Stopping);
        self.update_selection_state();

        let other_active = self.list_view.tunnels().iter().any(|t| {
            t.name != name && (t.state == TunnelState::Started || t.state == TunnelState::Starting)
        });
        let target_hwnd = parent_hwnd as isize;

        std::thread::spawn(move || {
            if let Ok(svc_name) = service_name_of_tunnel(&name) {
                if let Ok(scm) = ScmHandle::open(SC_MANAGER_ALL_ACCESS) {
                    if let Ok(svc) = scm.open_service(&svc_name, SERVICE_ALL_ACCESS) {
                        let _ = svc.stop_service();
                        let _ = svc.delete_service();
                    }
                }
            }

            let del_name = name.clone();
            let _ = wireguard_elevate::do_as_system(move || {
                if let Ok(dir) = ConfigDir::open_default() {
                    let _ = dir.delete_config(&del_name);
                }
                Ok(())
            });

            let conf_dir = ConfigDir::resolve_data_directory(false)
                .map(|root| root.join("Configurations"))
                .unwrap_or_else(|_| {
                    PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations")
                });
            let _ = std::fs::remove_file(conf_dir.join(format!("{name}.conf")));
            let _ = std::fs::remove_file(conf_dir.join(format!("{name}.conf.dpapi")));

            let _ = wireguard_manager::autostart::remove_autostart_tunnel(&name);
            if !other_active {
                let _ = wireguard_manager::autostart::set_windows_logon_autostart(false);
                log_to_file("All tunnels inactive after deletion: Windows logon auto-start disabled");
            }

            log_to_file(&format!("Deleted tunnel '{name}'"));
            post_tunnel_op_result(target_hwnd, TunnelOpResult::Deleted { tunnel_name: name });
        });
    }

    fn handle_tunnel_op_done(&mut self, result: TunnelOpResult) {
        match result {
            TunnelOpResult::AutostartSynced { any_started } => {
                if any_started {
                    self.poll_service_states();
                    post_tray_sync(self.hwnd);
                }
            }
            TunnelOpResult::Deactivated {
                tunnel_name,
                still_active,
            } => {
                self.pending_ops.remove(&tunnel_name);
                let final_state = if still_active {
                    query_tunnel_service_state(self.scm.as_ref(), &tunnel_name)
                } else {
                    TunnelState::Stopped
                };
                self.list_view
                    .update_tunnel_state(&tunnel_name, final_state);
                self.update_selection_state();
                post_tray_sync(self.hwnd);
            }
            TunnelOpResult::Activated { tunnel_name, error } => {
                self.pending_ops.remove(&tunnel_name);
                let live_state = query_tunnel_service_state(self.scm.as_ref(), &tunnel_name);
                let final_state = if error.is_none() && live_state == TunnelState::Stopped {
                    TunnelState::Started
                } else {
                    live_state
                };
                self.list_view
                    .update_tunnel_state(&tunnel_name, final_state);
                self.update_selection_state();
                post_tray_sync(self.hwnd);

                if let Some(err_msg) = error {
                    log_to_file(&format!(
                        "Failed to activate tunnel '{}': {}",
                        tunnel_name, err_msg
                    ));
                    let body = format!("Unable to activate tunnel ‘{tunnel_name}’:\n\n{err_msg}");
                    show_error_box(self.hwnd, "Error Activating Tunnel", &body);
                }
            }
            TunnelOpResult::Deleted { tunnel_name } => {
                self.pending_ops.remove(&tunnel_name);
                self.config_cache.remove(&tunnel_name);
                if self.rendered_tunnel_name.as_deref() == Some(tunnel_name.as_str()) {
                    self.rendered_tunnel_name = None;
                    self.details_dirty = true;
                }
                let _ = self.refresh_tunnels();
                self.update_selection_state();
                post_tray_sync(self.hwnd);
            }
            TunnelOpResult::ImportParsed { configs, errors } => {
                if !errors.is_empty() {
                    show_error_box(self.hwnd, "Import Error", &errors.join("\n"));
                }
                if configs.is_empty() {
                    return;
                }

                let mut approved = Vec::with_capacity(configs.len());
                for cfg in configs {
                    let already_exists = self.config_cache.contains_key(&cfg.name)
                        || self.list_view.tunnels().iter().any(|t| t.name == cfg.name);
                    if already_exists {
                        let prompt = format!(
                            "A tunnel with the name ‘{}’ already exists. Do you want to overwrite it?",
                            cfg.name
                        );
                        if !confirm_warning_yes_no(self.hwnd, "Overwrite Tunnel?", &prompt) {
                            continue;
                        }
                    }
                    approved.push(cfg);
                }

                if !approved.is_empty() {
                    spawn_import_save(self.hwnd as isize, approved);
                }
            }
            TunnelOpResult::Imported {
                configs,
                last_imported,
                errors,
            } => {
                if !errors.is_empty() {
                    show_error_box(self.hwnd, "Import Error", &errors.join("\n"));
                }
                if !configs.is_empty() {
                    for cfg in configs {
                        self.config_cache.insert(cfg.name.clone(), cfg);
                    }
                    self.details_dirty = true;
                    let _ = self.refresh_tunnels();
                    if let Some(ref name) = last_imported {
                        self.list_view.select_tunnel(name);
                    }
                    self.update_selection_state();
                    post_tray_sync(self.hwnd);
                }
            }
        }
    }
}

fn spawn_import_save(target_hwnd: isize, configs: Vec<TunnelConfig>) {
    std::thread::spawn(move || {
        let mut saved_configs = Vec::with_capacity(configs.len());
        let mut last_imported: Option<String> = None;
        let mut errors = Vec::new();

        for cfg in configs {
            let name = cfg.name.clone();
            let cfg_for_sys = cfg.clone();
            let sys_res = wireguard_elevate::do_as_system(move || match ConfigDir::open_default() {
                Ok(dir) => match dir.save_config(&cfg_for_sys, true) {
                    Ok(_) => Ok(Ok(())),
                    Err(e) => Ok(Err(e.to_string())),
                },
                Err(e) => Ok(Err(e.to_string())),
            });

            let mut saved_ok = matches!(sys_res, Ok(Ok(())));
            if !saved_ok {
                let fallback_res = match ConfigDir::resolve_data_directory(false) {
                    Ok(root) => {
                        let conf_dir = root.join("Configurations");
                        std::fs::create_dir_all(&conf_dir).and_then(|_| {
                            let target_path = conf_dir.join(format!("{name}.conf"));
                            let content = wireguard_conf::writer::to_wg_quick(&cfg);
                            std::fs::write(target_path, content.as_bytes())
                        })
                    }
                    Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                };

                if let Err(e) = fallback_res {
                    let sys_err = match sys_res {
                        Ok(Err(s)) => s,
                        Err(e) => e.to_string(),
                        Ok(Ok(())) => String::new(),
                    };
                    errors.push(format!("Could not save tunnel ‘{name}’: {e} ({sys_err})"));
                } else {
                    saved_ok = true;
                }
            }

            if saved_ok {
                log_to_file(&format!("Imported tunnel configuration '{name}'"));
                last_imported = Some(name);
                saved_configs.push(cfg);
            }
        }

        post_tunnel_op_result(
            target_hwnd,
            TunnelOpResult::Imported {
                configs: saved_configs,
                last_imported,
                errors,
            },
        );
    });
}

/// Win32 Window Procedure for the TunnelsPage composite.
unsafe extern "system" fn tunnels_page_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let inner_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut TunnelsPageInner;

    match msg {
        WM_SIZE => {
            let width = (lparam & 0xFFFF) as i32;
            let height = ((lparam >> 16) & 0xFFFF) as i32;

            if !inner_ptr.is_null() {
                (*inner_ptr).layout(width, height);
            }
            0
        }
        WM_COMMAND => {
            let ctrl_id = (wparam & 0xFFFF) as usize;
            if !inner_ptr.is_null() {
                match ctrl_id {
                    ID_BTN_ADD => (*inner_ptr).on_add_tunnel_menu(),
                    ID_BTN_IMPORT | ID_BTN_FILLER_IMPORT => (*inner_ptr).on_import_tunnel(),
                    ID_BTN_TOGGLE => (*inner_ptr).on_toggle_tunnel(),
                    ID_BTN_EDIT => (*inner_ptr).on_edit_tunnel(),
                    ID_BTN_DELETE => (*inner_ptr).on_delete_tunnel(),
                    _ => {}
                }
            }
            0
        }
        WM_NOTIFY => {
            let nmhdr = lparam as *const NMHDR;
            if !inner_ptr.is_null() && !nmhdr.is_null() {
                if (*inner_ptr).in_batch_update {
                    return 0;
                }

                let notify = (*inner_ptr).list_view.handle_notify(nmhdr);
                if let Some(event) = notify {
                    match event {
                        ListViewNotification::SelectionChanged(_) => {
                            (*inner_ptr).update_selection_state();
                        }
                        ListViewNotification::ItemActivated(_) => {
                            (*inner_ptr).on_toggle_tunnel();
                        }
                    }
                }
            }
            0
        }
        WM_APP_TUNNEL_OP_DONE => {
            if lparam != 0 {
                let result = Box::from_raw(lparam as *mut TunnelOpResult);
                if !inner_ptr.is_null() {
                    (*inner_ptr).handle_tunnel_op_done(*result);
                }
            }
            0
        }
        WM_ERASEBKGND => {
            let hdc = wparam as HDC;
            let mut rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            let brush = GetSysColorBrush(COLOR_BTNFACE as i32);
            FillRect(hdc, &rc, brush);
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = wparam as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            GetSysColorBrush(COLOR_BTNFACE as i32) as isize
        }
        WM_NCDESTROY => {
            let mut queued: MSG = std::mem::zeroed();
            while PeekMessageW(
                &mut queued,
                hwnd,
                WM_APP_TUNNEL_OP_DONE,
                WM_APP_TUNNEL_OP_DONE,
                PM_REMOVE,
            ) != 0
            {
                if queued.lParam != 0 {
                    drop(Box::from_raw(queued.lParam as *mut TunnelOpResult));
                }
            }
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Win32 Window Procedure for the details view and filler container.
unsafe extern "system" fn details_view_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let inner_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut TunnelsPageInner;

    match msg {
        WM_COMMAND => {
            let ctrl_id = (wparam & 0xFFFF) as usize;
            if !inner_ptr.is_null() {
                if ctrl_id == ID_BTN_FILLER_IMPORT || ctrl_id == ID_BTN_IMPORT {
                    (*inner_ptr).on_import_tunnel();
                }
            }
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = wparam as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            GetSysColorBrush(COLOR_WINDOW as i32) as isize
        }
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            if !inner_ptr.is_null() && hwnd == (*inner_ptr).details_container {
                (*inner_ptr).paint_dirty = false;
                let mut rc: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rc);
                let width = rc.right - rc.left;
                let height = rc.bottom - rc.top;

                if width > 0 && height > 0 {
                    let mem_dc = CreateCompatibleDC(hdc);
                    if !mem_dc.is_null() {
                        let mem_bmp = CreateCompatibleBitmap(hdc, width, height);
                        if !mem_bmp.is_null() {
                            let old_bmp = SelectObject(mem_dc, mem_bmp as HGDIOBJ);
                            render_details_view(mem_dc, hwnd, &*inner_ptr);
                            BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
                            SelectObject(mem_dc, old_bmp);
                            DeleteObject(mem_bmp as HGDIOBJ);
                            DeleteDC(mem_dc);
                        } else {
                            DeleteDC(mem_dc);
                            render_details_view(hdc, hwnd, &*inner_ptr);
                        }
                    } else {
                        render_details_view(hdc, hwnd, &*inner_ptr);
                    }
                } else {
                    render_details_view(hdc, hwnd, &*inner_ptr);
                }
            }

            EndPaint(hwnd, &ps);
            0
        }
        WM_ERASEBKGND => {
            if !inner_ptr.is_null() && hwnd == (*inner_ptr).details_container {
                // `WM_PAINT` double-buffers the entire details area, so skip erasing to eliminate flicker.
                return 1;
            }
            let hdc = wparam as HDC;
            let mut rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            let brush = GetSysColorBrush(COLOR_WINDOW as i32);
            FillRect(hdc, &rc, brush);
            1
        }
        WM_NCDESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Renders the tunnel interface and peer details inside the right pane with zero heap allocations.
unsafe fn render_details_view(hdc: HDC, hwnd: HWND, inner: &TunnelsPageInner) {
    let mut rc: RECT = std::mem::zeroed();
    GetClientRect(hwnd, &mut rc);

    // Fill background with standard window background
    let bg_brush = GetSysColorBrush(COLOR_WINDOW as i32);
    FillRect(hdc, &rc, bg_brush);

    if inner.rendered_details.title.is_empty() {
        return;
    }

    SetBkMode(hdc, TRANSPARENT as i32);

    let mut y = 14;
    let x_label = 16;
    let x_value = 130;
    let content_width = rc.right - x_value - 16;

    // Header: Tunnel Name
    SelectObject(hdc, inner.font_large as HGDIOBJ);
    SetTextColor(hdc, 0x00000000); // Black
    let mut r_header = RECT {
        left: x_label,
        top: y,
        right: rc.right - 16,
        bottom: y + 26,
    };
    DrawTextW(
        hdc,
        inner.rendered_details.title.as_ptr(),
        -1,
        &mut r_header,
        DT_LEFT | DT_SINGLELINE | DT_NOPREFIX,
    );
    y += 34;

    // Status Line
    let labels = details_labels();

    SelectObject(hdc, inner.font_bold as HGDIOBJ);
    let mut r_lbl = RECT {
        left: x_label,
        top: y,
        right: x_value,
        bottom: y + 20,
    };
    DrawTextW(
        hdc,
        labels.status.as_ptr(),
        -1,
        &mut r_lbl,
        DT_LEFT | DT_SINGLELINE,
    );

    SelectObject(hdc, inner.font as HGDIOBJ);
    let mut r_val = RECT {
        left: x_value,
        top: y,
        right: rc.right - 16,
        bottom: y + 20,
    };
    let (status_color, status_ptr) = match inner.selected_state {
        TunnelState::Started => (0x002E7D32, labels.active.as_ptr()),
        TunnelState::Starting => (0x000080C0, labels.activating.as_ptr()),
        TunnelState::Stopping => (0x000080C0, labels.deactivating.as_ptr()),
        TunnelState::Stopped | TunnelState::Unknown => (0x00757575, labels.inactive.as_ptr()),
    };
    SetTextColor(hdc, status_color);
    DrawTextW(
        hdc,
        status_ptr,
        -1,
        &mut r_val,
        DT_LEFT | DT_SINGLELINE,
    );
    SetTextColor(hdc, 0x00000000);
    y += 24;

    // Interface fields
    for field in &inner.rendered_details.interface_fields {
        draw_field_cached(
            hdc,
            inner.font_bold,
            inner.font,
            x_label,
            x_value,
            &mut y,
            content_width,
            field.label,
            &field.value,
        );
    }

    // Peer sections
    for peer in &inner.rendered_details.peers {
        y += 10;
        SelectObject(hdc, inner.font_bold as HGDIOBJ);
        let mut r_peer = RECT {
            left: x_label,
            top: y,
            right: rc.right - 16,
            bottom: y + 20,
        };
        DrawTextW(
            hdc,
            peer.title.as_ptr(),
            -1,
            &mut r_peer,
            DT_LEFT | DT_SINGLELINE,
        );
        y += 24;

        for field in &peer.fields {
            draw_field_cached(
                hdc,
                inner.font_bold,
                inner.font,
                x_label,
                x_value,
                &mut y,
                content_width,
                field.label,
                &field.value,
            );
        }
    }
}

/// Helper function to draw a pre-encoded UTF-16 label-value row in the details view.
unsafe fn draw_field_cached(
    hdc: HDC,
    font_bold: HFONT,
    font: HFONT,
    x_label: i32,
    x_value: i32,
    y: &mut i32,
    content_width: i32,
    label_w: &[u16],
    value_w: &[u16],
) {
    SelectObject(hdc, font_bold as HGDIOBJ);
    let mut r_lbl = RECT {
        left: x_label,
        top: *y,
        right: x_value,
        bottom: *y + 20,
    };
    DrawTextW(
        hdc,
        label_w.as_ptr(),
        -1,
        &mut r_lbl,
        DT_LEFT | DT_SINGLELINE | DT_NOPREFIX,
    );

    SelectObject(hdc, font as HGDIOBJ);
    let mut r_val = RECT {
        left: x_value,
        top: *y,
        right: x_value + content_width,
        bottom: *y + 20,
    };
    DrawTextW(
        hdc,
        value_w.as_ptr(),
        -1,
        &mut r_val,
        DT_LEFT | DT_WORDBREAK | DT_NOPREFIX,
    );

    *y += 22;
}
