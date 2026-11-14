// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Native Win32 Main UI Window, Tab Control, and Application Lifecycle Manager.
//!
//! Faithfully ported from `wireguard-windows/ui/managewindow.go` and `wireguard-windows/ui/ui.go`.
//!
//! Responsibilities:
//! - Window class registration ("WireGuard UI - Manage Tunnels").
//! - Main window creation with `WS_OVERLAPPEDWINDOW`, centered default size (675x525),
//!   enforced minimum size (500x400 via `WM_GETMINMAXINFO`).
//! - Tab Control management (`WC_TABCONTROLW`) with 2 tabs: "Tunnels" (index 0) and "Log" (index 1).
//! - Responsive layout calculations on `WM_SIZE` using `TCM_ADJUSTRECT` and `MapWindowPoints`.
//! - Smooth tab page switching on `TCN_SELCHANGE`.
//! - Close-to-tray behavior on `WM_CLOSE` (hides window instead of destroying if tray is active).
//! - Custom raise message dispatching (`WM_USER + 0x3510`) with UIPI bypass.
//! - System tray integration and Win32 message pump (`run_ui`).

use std::path::PathBuf;
use std::ptr;
use std::thread::JoinHandle;
use tracing::{debug, info, warn};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CLASS_ALREADY_EXISTS, GetLastError, BOOL, HANDLE, HWND,
    INVALID_HANDLE_VALUE, LPARAM, LRESULT, POINT, RECT, TRUE, WAIT_OBJECT_0, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, GetSysColorBrush, InvalidateRect, MapWindowPoints, UpdateWindow,
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, COLOR_BTNFACE, DEFAULT_CHARSET, DEFAULT_PITCH,
    FF_DONTCARE, FW_NORMAL, HFONT, OUT_DEFAULT_PRECIS,
};
use windows_sys::Win32::Storage::FileSystem::{
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, SetEvent, SetProcessPriorityBoost, WaitForMultipleObjects,
    WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_LISTVIEW_CLASSES, ICC_STANDARD_CLASSES, ICC_TAB_CLASSES,
    INITCOMMONCONTROLSEX, NMHDR, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT, TCM_GETCURSEL,
    TCM_INSERTITEMW, TCM_SETCURSEL, TCN_SELCHANGE, WC_TABCONTROLW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetClientRect, GetMessageW, GetSystemMenu, GetSystemMetrics, GetWindowLongPtrW,
    InsertMenuItemW, IsIconic, IsWindowVisible, KillTimer, LoadCursorW, LoadIconW, PostMessageW,
    PostQuitMessage, RegisterClassExW, SendMessageW, SetForegroundWindow, SetTimer,
    SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TranslateMessage, CS_DBLCLKS,
    CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA, HWND_BOTTOM, ICON_BIG, ICON_SMALL, IDC_ARROW,
    IDI_APPLICATION, MENUITEMINFOW, MFT_SEPARATOR, MFT_STRING, MIIM_FTYPE, MIIM_ID,
    MIIM_STRING, MINMAXINFO, MSG, SC_MINIMIZE, SIZE_MINIMIZED, SM_CXSCREEN, SM_CYSCREEN,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE, SW_MINIMIZE, SW_RESTORE,
    SW_SHOW, SW_SHOWNORMAL, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_ENDSESSION,
    WM_GETMINMAXINFO, WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY, WM_QUERYENDSESSION, WM_SETFONT,
    WM_SETICON, WM_SHOWWINDOW, WM_SIZE, WM_SYSCOMMAND, WM_TIMER, WNDCLASSEXW, WS_CHILD,
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_EX_CONTROLPARENT, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

use crate::win32_util::{
    to_wide_null, with_wide_null, WM_APP_CONFIGS_CHANGED, WM_APP_SERVICE_STATE_CHANGED,
    WM_APP_TRAY_SYNC,
};

pub use crate::raise::{MANAGE_WINDOW_CLASS, WM_RAISE_MSG};
pub use crate::tray::WM_TRAY_CALLBACK;

/// Win32 Window Class Name for child tab page container hosts.
pub const TAB_PAGE_CLASS: &str = "WireGuard UI - Tab Page";

/// Command ID for the system menu "&About WireGuard..." entry.
pub const IDM_ABOUT_WIREGUARD: u32 = 0x37;

/// Control IDs for child controls and tabs.
pub const IDC_TAB_CONTROL: usize = 1001;
pub const IDC_TUNNELS_PAGE: usize = 1002;
pub const IDC_LOG_PAGE: usize = 1003;

/// Timer ID & interval for the Log tab (runs ONLY while visible on the Log tab).
const IDT_LOG_TIMER: usize = 1;
const LOG_POLL_INTERVAL_MS: u32 = 1000;

/// Tab indices in the Tab Control.
pub const TAB_INDEX_TUNNELS: usize = 0;
pub const TAB_INDEX_LOG: usize = 1;

/// Default and constraint window dimensions matching WireGuard Windows specification.
pub const DEFAULT_WIDTH: i32 = 675;
pub const DEFAULT_HEIGHT: i32 = 525;
pub const MIN_WIDTH: i32 = 500;
pub const MIN_HEIGHT: i32 = 400;
pub const MARGIN: i32 = 5;

#[derive(Clone, Copy)]
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

#[derive(Clone, Copy)]
struct SendHwnd(HWND);
unsafe impl Send for SendHwnd {}
unsafe impl Sync for SendHwnd {}

/// Registers the main window class and tab page class once per process.
fn ensure_window_classes_registered() -> Result<(), Box<dyn std::error::Error>> {
    static REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if REGISTERED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }

    let hinstance = unsafe { GetModuleHandleW(ptr::null()) };

    // 1. Register Main Window Class ("WireGuard UI - Manage Tunnels")
    let h_icon = crate::icons::create_logo_icon(32)
        .map(|ic| ic.into_raw())
        .unwrap_or_else(|_| unsafe { LoadIconW(ptr::null_mut(), IDI_APPLICATION) });
    let h_icon_sm = crate::icons::create_logo_icon(16)
        .map(|ic| ic.into_raw())
        .unwrap_or(ptr::null_mut());
    let h_cursor = unsafe { LoadCursorW(ptr::null_mut(), IDC_ARROW) };
    let h_br = unsafe { GetSysColorBrush(COLOR_BTNFACE) };

    let atom = with_wide_null(MANAGE_WINDOW_CLASS, |class_ptr| unsafe {
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
        wc.lpfnWndProc = Some(manage_window_proc);
        wc.hInstance = hinstance;
        wc.hIcon = h_icon;
        wc.hIconSm = h_icon_sm;
        wc.hCursor = h_cursor;
        wc.hbrBackground = h_br;
        wc.lpszClassName = class_ptr;
        RegisterClassExW(&wc)
    });
    if atom == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_CLASS_ALREADY_EXISTS {
            warn!(
                "Failed to register window class '{}': Win32 error {}",
                MANAGE_WINDOW_CLASS, err
            );
        }
    }

    // 2. Register Tab Page Class ("WireGuard UI - Tab Page")
    with_wide_null(TAB_PAGE_CLASS, |page_class_ptr| unsafe {
        let mut wc_page: WNDCLASSEXW = std::mem::zeroed();
        wc_page.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc_page.style = CS_HREDRAW | CS_VREDRAW;
        wc_page.lpfnWndProc = Some(tab_page_proc);
        wc_page.hInstance = hinstance;
        wc_page.hCursor = h_cursor;
        wc_page.hbrBackground = h_br;
        wc_page.lpszClassName = page_class_ptr;
        RegisterClassExW(&wc_page);
    });

    // 3. Initialize Common Controls for Tab Control and ListView
    let icex = INITCOMMONCONTROLSEX {
        dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_TAB_CLASSES | ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES,
    };
    unsafe {
        InitCommonControlsEx(&icex);
    }

    Ok(())
}

/// Allows `WM_RAISE_MSG` across User Interface Privilege Isolation (UIPI).
fn allow_uipi_raise_message(hwnd: HWND) {
    unsafe {
        let user32 = with_wide_null("user32.dll", |p| GetModuleHandleW(p));
        if !user32.is_null() {
            let proc = GetProcAddress(user32, b"ChangeWindowMessageFilterEx\0".as_ptr());
            if let Some(change_filter) = proc {
                type ChangeWindowMessageFilterExFn = unsafe extern "system" fn(
                    HWND,
                    u32,
                    u32,
                    *mut core::ffi::c_void,
                ) -> BOOL;
                let func: ChangeWindowMessageFilterExFn = std::mem::transmute(change_filter);
                func(hwnd, WM_RAISE_MSG, 1 /* MSGFLT_ALLOW */, ptr::null_mut());
            }
        }
    }
}

/// Appends diagnostic log messages to the in-memory UI log page buffer and shared ringlog.
/// Does not create any external `.log` file next to the executable.
pub fn log_to_file(msg: &str) {
    crate::logpage::append_ui_log_line(msg);
}

/// Window procedure for child tab page container hosts.
pub unsafe extern "system" fn tab_page_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// Win32 Main UI Window Manager managing tabs, child pages, and system tray integration.
pub struct ManageTunnelsWindow {
    /// Window handle to the main top-level window.
    pub hwnd: HWND,
    /// Handle to the Win32 Tab Control (`WC_TABCONTROLW`).
    pub hwnd_tab: HWND,
    /// Handle to the primary Tunnels Page child window.
    pub hwnd_tunnels_page: HWND,
    /// Handle to the Log Page child window container.
    pub hwnd_log_page: HWND,
    /// High-level TunnelsPage instance managing tunnel list and configuration details.
    pub tunnels_page: Option<crate::tunnelspage::TunnelsPage>,
    /// High-level LogPage instance managing log viewing and export.
    pub log_page: Option<crate::logpage::LogPage>,
    /// Array of child page window handles corresponding to tabs.
    pub child_pages: Vec<HWND>,
    /// System tray notification icon manager.
    pub tray: Option<crate::tray::Tray>,
    /// Shared Segoe UI font handle for native typography.
    pub hfont: HFONT,
    /// Flag indicating whether closing the window hides to tray instead of exiting.
    pub tray_active: bool,
    /// Tracks whether the conditional Log-tab Win32 timer is currently armed.
    log_timer_active: bool,
    /// Last visibility state delivered to `TunnelsPage::on_visibility_changed`.
    last_tunnels_visible: bool,
    /// Last visibility state delivered to `LogPage::on_visibility_changed`.
    last_log_visible: bool,
    /// Manual-reset Win32 Event handle signaling the config directory watcher to stop.
    dir_cancel: Option<SendHandle>,
    dir_watcher_thread: Option<JoinHandle<()>>,
    /// Cancel handle signaling the event-driven SCM service watcher to stop.
    scm_cancel: Option<wireguard_service::ScmWatchCancel>,
    scm_watcher_thread: Option<JoinHandle<()>>,
}

impl ManageTunnelsWindow {
    /// Creates and initializes the main Manage Tunnels window, centered on screen and initially hidden.
    pub fn new() -> Result<Box<Self>, Box<dyn std::error::Error>> {
        log_to_file("ManageTunnelsWindow::new(): registering classes");
        ensure_window_classes_registered()?;

        let mut mtw = Box::new(ManageTunnelsWindow {
            hwnd: ptr::null_mut(),
            hwnd_tab: ptr::null_mut(),
            hwnd_tunnels_page: ptr::null_mut(),
            hwnd_log_page: ptr::null_mut(),
            tunnels_page: None,
            log_page: None,
            child_pages: Vec::new(),
            tray: None,
            hfont: ptr::null_mut(),
            tray_active: true,
            log_timer_active: false,
            last_tunnels_visible: false,
            last_log_visible: false,
            dir_cancel: None,
            dir_watcher_thread: None,
            scm_cancel: None,
            scm_watcher_thread: None,
        });

        // Compute screen-centered initial position
        let screen_w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let screen_h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        let x = ((screen_w - DEFAULT_WIDTH) / 2).max(0);
        let y = ((screen_h - DEFAULT_HEIGHT) / 2).max(0);

        let hinstance = unsafe { GetModuleHandleW(ptr::null()) };

        let raw_ptr: *mut ManageTunnelsWindow = &mut *mtw;

        log_to_file("ManageTunnelsWindow::new(): calling CreateWindowExW for main window (initially hidden)");
        // NOTE: Do NOT pass WS_VISIBLE here so tray-only startups create a genuinely hidden window
        // without flashing on screen before WM_CLOSE/hide.
        let hwnd = with_wide_null(MANAGE_WINDOW_CLASS, |class_ptr| {
            with_wide_null("WireGuard", |title_ptr| unsafe {
                CreateWindowExW(
                    WS_EX_CONTROLPARENT,
                    class_ptr,
                    title_ptr,
                    WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                    x,
                    y,
                    DEFAULT_WIDTH,
                    DEFAULT_HEIGHT,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    hinstance,
                    raw_ptr as *mut _,
                )
            })
        });

        if hwnd.is_null() {
            let err = unsafe { GetLastError() };
            log_to_file(&format!("ManageTunnelsWindow::new(): CreateWindowExW FAILED with error {}", err));
            return Err(format!("CreateWindowExW failed for WireGuard Manage Tunnels window (Win32 error: {})", err).into());
        }

        log_to_file(&format!("ManageTunnelsWindow::new(): CreateWindowExW succeeded, HWND: {:?}", hwnd));
        mtw.hwnd = hwnd;
        Ok(mtw)
    }

    /// Returns the main window handle.
    pub fn handle(&self) -> HWND {
        self.hwnd
    }

    /// Sets the window caption title.
    pub fn set_title(&self, title: &str) {
        if !self.hwnd.is_null() {
            with_wide_null(title, |wide| unsafe {
                SetWindowTextW(self.hwnd, wide);
            });
        }
    }

    /// Sets the close-to-tray operational flag.
    pub fn set_tray_active(&mut self, active: bool) {
        self.tray_active = active;
    }

    /// Returns whether close-to-tray is enabled.
    pub fn is_tray_active(&self) -> bool {
        self.tray_active
    }

    /// Shows and activates the main window.
    pub fn show(&mut self) {
        if !self.hwnd.is_null() {
            unsafe {
                ShowWindow(self.hwnd, SW_SHOWNORMAL);
                UpdateWindow(self.hwnd);
                SetForegroundWindow(self.hwnd);
                BringWindowToTop(self.hwnd);
            }
            self.update_log_timer_and_visibility(None);
        }
    }

    /// Hides the main window (minimizing to tray) and stops the Log polling timer.
    pub fn hide(&mut self) {
        if !self.hwnd.is_null() {
            unsafe {
                ShowWindow(self.hwnd, SW_HIDE);
            }
            self.update_log_timer_and_visibility(Some(false));
        }
    }

    /// Minimizes the main window to taskbar.
    pub fn minimize(&self) {
        if !self.hwnd.is_null() {
            unsafe {
                ShowWindow(self.hwnd, SW_MINIMIZE);
            }
        }
    }

    /// Restores the main window to normal geometry.
    pub fn restore(&self) {
        if !self.hwnd.is_null() {
            unsafe {
                ShowWindow(self.hwnd, SW_RESTORE);
            }
        }
    }

    /// Brings the window to the foreground using the topmost toggle technique.
    pub fn raise(&self) {
        if !self.hwnd.is_null() {
            crate::raise::raise(self.hwnd);
        }
    }

    /// Selects the tab at index `index` (0 = Tunnels, 1 = Log) and switches visible pages.
    pub fn select_tab(&mut self, index: usize) {
        if self.hwnd_tab.is_null() || index >= self.child_pages.len() {
            return;
        }
        unsafe {
            SendMessageW(self.hwnd_tab, TCM_SETCURSEL, index, 0);
        }
        self.on_tab_change();
    }

    /// Returns the current active tab index.
    pub fn current_tab(&self) -> usize {
        if self.hwnd_tab.is_null() {
            return 0;
        }
        let sel = unsafe { SendMessageW(self.hwnd_tab, TCM_GETCURSEL, 0, 0) as isize };
        if sel < 0 {
            0
        } else {
            sel as usize
        }
    }

    /// Internal UI builder called during `WM_CREATE`.
    pub fn setup_ui(&mut self, hwnd: HWND) {
        let hinstance = unsafe { GetModuleHandleW(ptr::null()) };

        // 1. Create clean Segoe UI typography font (-12px, approx 9pt)
        let hfont = with_wide_null("Segoe UI", |font_ptr| unsafe {
            CreateFontW(
                -12,
                0,
                0,
                0,
                FW_NORMAL as i32,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                (DEFAULT_PITCH | FF_DONTCARE) as u32,
                font_ptr,
            )
        });
        self.hfont = hfont;

        // 2. Query initial client bounds
        let mut client_rc: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            GetClientRect(hwnd, &mut client_rc);
        }
        let tab_w = (client_rc.right - client_rc.left) - 2 * MARGIN;
        let tab_h = (client_rc.bottom - client_rc.top) - 2 * MARGIN;

        // 3. Create Win32 Tab Control (`WC_TABCONTROLW`)
        let hwnd_tab = unsafe {
            CreateWindowExW(
                0,
                WC_TABCONTROLW,
                ptr::null(),
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
                MARGIN,
                MARGIN,
                tab_w.max(10),
                tab_h.max(10),
                hwnd,
                IDC_TAB_CONTROL as _,
                hinstance,
                ptr::null_mut(),
            )
        };
        self.hwnd_tab = hwnd_tab;

        if !hfont.is_null() && !hwnd_tab.is_null() {
            unsafe {
                SendMessageW(hwnd_tab, WM_SETFONT, hfont as WPARAM, 1);
            }
        }

        // 4. Insert Tab 0: "Tunnels"
        let mut text_tunnels = to_wide_null("Tunnels");
        let item_tunnels = TCITEMW {
            mask: TCIF_TEXT,
            dwState: 0,
            dwStateMask: 0,
            pszText: text_tunnels.as_mut_ptr(),
            cchTextMax: 0,
            iImage: -1,
            lParam: 0,
        };
        unsafe {
            SendMessageW(
                hwnd_tab,
                TCM_INSERTITEMW,
                TAB_INDEX_TUNNELS,
                &item_tunnels as *const _ as LPARAM,
            );
        }

        // 5. Insert Tab 1: "Log"
        let mut text_log = to_wide_null("Log");
        let item_log = TCITEMW {
            mask: TCIF_TEXT,
            dwState: 0,
            dwStateMask: 0,
            pszText: text_log.as_mut_ptr(),
            cchTextMax: 0,
            iImage: -1,
            lParam: 0,
        };
        unsafe {
            SendMessageW(
                hwnd_tab,
                TCM_INSERTITEMW,
                TAB_INDEX_LOG,
                &item_log as *const _ as LPARAM,
            );
        }

        // 6. Compute tab content display rectangle
        let mut tab_rc: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            GetClientRect(hwnd_tab, &mut tab_rc);
            SendMessageW(hwnd_tab, TCM_ADJUSTRECT, 0, &mut tab_rc as *const _ as LPARAM);
            MapWindowPoints(hwnd_tab, hwnd, &mut tab_rc as *mut _ as *mut POINT, 2);
        }

        let page_w = (tab_rc.right - tab_rc.left).max(10);
        let page_h = (tab_rc.bottom - tab_rc.top).max(10);

        // 7. Instantiate TunnelsPage on Tab 0 (initially visible inside hidden parent)
        log_to_file("setup_ui(): instantiating TunnelsPage...");
        match crate::tunnelspage::TunnelsPage::new(hwnd, tab_rc) {
            Ok(page) => {
                let page_hwnd = page.hwnd();
                self.hwnd_tunnels_page = page_hwnd;
                self.tunnels_page = Some(page);
                log_to_file(&format!("setup_ui(): TunnelsPage initialized successfully, HWND={:?}", page_hwnd));
                debug!("TunnelsPage initialized successfully (HWND={:?})", page_hwnd);
            }
            Err(e) => {
                log_to_file(&format!("setup_ui(): TunnelsPage initialization failed: {}", e));
                warn!(
                    "Failed to initialize TunnelsPage: {}. Falling back to container window.",
                    e
                );
                let fallback_hwnd = with_wide_null(TAB_PAGE_CLASS, |page_class| unsafe {
                    CreateWindowExW(
                        WS_EX_CONTROLPARENT,
                        page_class,
                        ptr::null(),
                        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                        tab_rc.left,
                        tab_rc.top,
                        page_w,
                        page_h,
                        hwnd,
                        IDC_TUNNELS_PAGE as _,
                        hinstance,
                        ptr::null_mut(),
                    )
                });
                self.hwnd_tunnels_page = fallback_hwnd;
            }
        }

        // 8. Instantiate LogPage on Tab 1 (initially hidden)
        log_to_file("setup_ui(): instantiating LogPage...");
        match crate::logpage::LogPage::new(hwnd, tab_rc) {
            Ok(page) => {
                let log_hwnd = page.hwnd();
                self.hwnd_log_page = log_hwnd;
                self.log_page = Some(page);
                unsafe {
                    ShowWindow(log_hwnd, SW_HIDE);
                }
                log_to_file(&format!("setup_ui(): LogPage initialized successfully, HWND={:?}", log_hwnd));
            }
            Err(e) => {
                log_to_file(&format!("setup_ui(): LogPage initialization failed: {}", e));
                let fallback_hwnd = with_wide_null(TAB_PAGE_CLASS, |page_class| unsafe {
                    CreateWindowExW(
                        WS_EX_CONTROLPARENT,
                        page_class,
                        ptr::null(),
                        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                        tab_rc.left,
                        tab_rc.top,
                        page_w,
                        page_h,
                        hwnd,
                        IDC_LOG_PAGE as _,
                        hinstance,
                        ptr::null_mut(),
                    )
                });
                self.hwnd_log_page = fallback_hwnd;
            }
        }

        self.child_pages = vec![self.hwnd_tunnels_page, self.hwnd_log_page];

        // 9. Setup System Menu ("&About WireGuard...")
        let sys_menu = unsafe { GetSystemMenu(hwnd, 0) };
        if !sys_menu.is_null() {
            let mut about_text = to_wide_null("&About WireGuard…");
            let mut mii: MENUITEMINFOW = unsafe { std::mem::zeroed() };
            mii.cbSize = std::mem::size_of::<MENUITEMINFOW>() as u32;
            mii.fMask = MIIM_ID | MIIM_STRING | MIIM_FTYPE;
            mii.fType = MFT_STRING;
            mii.wID = IDM_ABOUT_WIREGUARD;
            mii.dwTypeData = about_text.as_mut_ptr();
            unsafe {
                InsertMenuItemW(sys_menu, 0, 1, &mii);
            }

            let mut sep: MENUITEMINFOW = unsafe { std::mem::zeroed() };
            sep.cbSize = std::mem::size_of::<MENUITEMINFOW>() as u32;
            sep.fMask = MIIM_FTYPE;
            sep.fType = MFT_SEPARATOR;
            unsafe {
                InsertMenuItemW(sys_menu, 1, 1, &sep);
            }
        }

        // 10. Load and set application shield logo icons
        if let Ok(logo32) = crate::icons::create_logo_icon(32) {
            unsafe {
                SendMessageW(
                    hwnd,
                    WM_SETICON,
                    ICON_BIG as WPARAM,
                    logo32.into_raw() as LPARAM,
                );
            }
        }
        if let Ok(logo16) = crate::icons::create_logo_icon(16) {
            unsafe {
                SendMessageW(
                    hwnd,
                    WM_SETICON,
                    ICON_SMALL as WPARAM,
                    logo16.into_raw() as LPARAM,
                );
            }
        }

        // 11. Allow UIPI cross-process activation for `WM_RAISE_MSG`
        allow_uipi_raise_message(hwnd);

        // 12. Ensure Z-order: Tab control at bottom, TunnelsPage child ready on top.
        // No polling SetTimer is started here; updates are event-driven and the Log
        // timer is started only when the window is visible on the Log tab.
        unsafe {
            SetWindowPos(
                self.hwnd_tab,
                HWND_BOTTOM,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
            if !self.hwnd_tunnels_page.is_null() {
                ShowWindow(self.hwnd_tunnels_page, SW_SHOW);
                BringWindowToTop(self.hwnd_tunnels_page);
                InvalidateRect(self.hwnd_tunnels_page, ptr::null(), 1);
                UpdateWindow(self.hwnd_tunnels_page);
            }
        }
    }

    /// Handles window resizing by laying out the Tab Control and child pages.
    pub fn on_size(&mut self, width: i32, height: i32) {
        if self.hwnd_tab.is_null() {
            return;
        }

        let tab_w = (width - 2 * MARGIN).max(10);
        let tab_h = (height - 2 * MARGIN).max(10);

        unsafe {
            SetWindowPos(
                self.hwnd_tab,
                HWND_BOTTOM,
                MARGIN,
                MARGIN,
                tab_w,
                tab_h,
                SWP_NOACTIVATE,
            );
        }

        // Compute inner display rectangle
        let mut tab_rc: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            GetClientRect(self.hwnd_tab, &mut tab_rc);
            SendMessageW(self.hwnd_tab, TCM_ADJUSTRECT, 0, &mut tab_rc as *const _ as LPARAM);
            MapWindowPoints(self.hwnd_tab, self.hwnd, &mut tab_rc as *mut _ as *mut POINT, 2);
        }

        let page_w = (tab_rc.right - tab_rc.left).max(0);
        let page_h = (tab_rc.bottom - tab_rc.top).max(0);

        // Resize TunnelsPage composite
        if let Some(ref mut page) = self.tunnels_page {
            page.resize(tab_rc);
        } else if !self.hwnd_tunnels_page.is_null() {
            unsafe {
                SetWindowPos(
                    self.hwnd_tunnels_page,
                    ptr::null_mut(),
                    tab_rc.left,
                    tab_rc.top,
                    page_w,
                    page_h,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
        }

        // Resize other child pages (e.g. LogPage host)
        if let Some(ref mut page) = self.log_page {
            page.resize(tab_rc);
        } else {
            for &page_hwnd in self.child_pages.iter().skip(1) {
                if !page_hwnd.is_null() {
                    unsafe {
                        SetWindowPos(
                            page_hwnd,
                            ptr::null_mut(),
                            tab_rc.left,
                            tab_rc.top,
                            page_w,
                            page_h,
                            SWP_NOZORDER | SWP_NOACTIVATE,
                        );
                    }
                }
            }
        }

        let cur_sel = self.current_tab();
        if let Some(&active_hwnd) = self.child_pages.get(cur_sel) {
            if !active_hwnd.is_null() {
                unsafe {
                    BringWindowToTop(active_hwnd);
                }
            }
        }
    }

    /// Handles tab selection changes (`TCN_SELCHANGE`).
    pub fn on_tab_change(&mut self) {
        if self.hwnd_tab.is_null() {
            return;
        }

        let cur_sel = unsafe { SendMessageW(self.hwnd_tab, TCM_GETCURSEL, 0, 0) as usize };

        unsafe {
            SetWindowPos(
                self.hwnd_tab,
                HWND_BOTTOM,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }

        for (i, &page_hwnd) in self.child_pages.iter().enumerate() {
            if !page_hwnd.is_null() {
                if i == cur_sel {
                    unsafe {
                        ShowWindow(page_hwnd, SW_SHOW);
                        BringWindowToTop(page_hwnd);
                        InvalidateRect(page_hwnd, ptr::null(), 1);
                        UpdateWindow(page_hwnd);
                    }
                } else {
                    unsafe {
                        ShowWindow(page_hwnd, SW_HIDE);
                    }
                }
            }
        }

        self.update_log_timer_and_visibility(None);
    }

    /// Returns `true` when the main window is visible, unminimized, and showing the Log tab.
    fn is_log_tab_actively_visible(&self) -> bool {
        !self.hwnd.is_null()
            && unsafe { IsWindowVisible(self.hwnd) != 0 && IsIconic(self.hwnd) == 0 }
            && self.current_tab() == TAB_INDEX_LOG
    }

    /// Synchronizes conditional Log-tab `SetTimer`/`KillTimer` and notifies pages on visibility transitions.
    fn update_log_timer_and_visibility(&mut self, visible_override: Option<bool>) {
        if self.hwnd.is_null() {
            return;
        }
        let win_visible = visible_override.unwrap_or_else(|| unsafe { IsWindowVisible(self.hwnd) != 0 });
        let unminimized = unsafe { IsIconic(self.hwnd) == 0 };
        let tab = self.current_tab();

        let tunnels_visible = win_visible && unminimized && tab == TAB_INDEX_TUNNELS;
        let log_visible = win_visible && unminimized && tab == TAB_INDEX_LOG;

        if log_visible {
            if !self.log_timer_active {
                unsafe {
                    SetTimer(self.hwnd, IDT_LOG_TIMER, LOG_POLL_INTERVAL_MS, None);
                }
                self.log_timer_active = true;
            }
        } else if self.log_timer_active {
            unsafe {
                KillTimer(self.hwnd, IDT_LOG_TIMER);
            }
            self.log_timer_active = false;
        }

        if log_visible != self.last_log_visible {
            self.last_log_visible = log_visible;
            if let Some(ref mut page) = self.log_page {
                page.on_visibility_changed(log_visible);
            }
        }

        if tunnels_visible != self.last_tunnels_visible {
            self.last_tunnels_visible = tunnels_visible;
            if let Some(ref mut page) = self.tunnels_page {
                page.on_visibility_changed(tunnels_visible);
            }
        }
    }

    /// Synchronizes the system tray icon, tooltip, and context menu tunnel list with live tunnel states.
    pub fn sync_tray_state(&mut self) {
        let Some(ref page) = self.tunnels_page else {
            return;
        };
        let Some(ref mut tray) = self.tray else {
            return;
        };

        let items = page.tunnels();
        tray.sync_tunnel_states(items.iter().map(|t| (t.name.as_str(), t.state)));
    }

    /// Handles `WM_APP_CONFIGS_CHANGED` from the `Configurations` directory watcher thread.
    pub fn on_configs_changed(&mut self) {
        if let Some(ref mut page) = self.tunnels_page {
            page.on_configs_changed();
        }
        self.sync_tray_state();
    }

    /// Handles `WM_APP_SERVICE_STATE_CHANGED` from the SCM notification watcher thread.
    pub fn on_service_state_changed(&mut self) {
        if let Some(ref mut page) = self.tunnels_page {
            page.on_service_state_changed();
        }
        self.sync_tray_state();
    }

    /// Periodic 1-second timer callback used exclusively while the Log tab is visible.
    pub fn on_timer(&mut self, timer_id: usize) {
        if timer_id != IDT_LOG_TIMER {
            return;
        }
        if !self.is_log_tab_actively_visible() {
            if self.log_timer_active && !self.hwnd.is_null() {
                unsafe {
                    KillTimer(self.hwnd, IDT_LOG_TIMER);
                }
                self.log_timer_active = false;
            }
            return;
        }
        if let Some(ref mut page) = self.log_page {
            page.poll_new_logs();
        }
    }

    /// Starts event-driven background watchers (`Configurations` directory and SCM services).
    pub fn start_watchers(&mut self) {
        if self.hwnd.is_null() {
            return;
        }
        self.stop_watchers();

        let target_hwnd = SendHwnd(self.hwnd);

        // 1. Cancelable Configurations directory watcher thread (FindFirstChangeNotificationW + Event)
        let cancel_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if !cancel_event.is_null() {
            let cancel_handle = SendHandle(cancel_event);
            let conf_dir = wireguard_manager::ConfigDirManager::resolve_data_directory(false)
                .map(|p| p.join("Configurations"))
                .unwrap_or_else(|_| PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations"));

            match std::thread::Builder::new()
                .name("wg-configs-watch".into())
                .spawn(move || run_config_dir_watcher(target_hwnd, conf_dir, cancel_handle))
            {
                Ok(join) => {
                    self.dir_cancel = Some(cancel_handle);
                    self.dir_watcher_thread = Some(join);
                }
                Err(e) => {
                    warn!("Failed to spawn config directory watcher thread: {}", e);
                    unsafe {
                        CloseHandle(cancel_event);
                    }
                }
            }
        } else {
            warn!("CreateEventW failed for config watcher (Win32 error: {})", unsafe {
                GetLastError()
            });
        }

        // 2. Event-driven SCM watcher thread via wireguard-service NotifyServiceStatusChangeW
        match wireguard_service::ScmWatchCancel::new() {
            Ok(scm_cancel) => {
                let scm_cancel_worker = scm_cancel.clone();
                match std::thread::Builder::new()
                    .name("wg-scm-watch".into())
                    .spawn(move || {
                        let target_hwnd = target_hwnd;
                        while !scm_cancel_worker.is_cancelled() {
                            match wireguard_service::watch_services(
                                Some("WireGuardTunnel$"),
                                &scm_cancel_worker,
                                move |_changes| unsafe {
                                    let target_hwnd = target_hwnd;
                                    let _ = PostMessageW(
                                        target_hwnd.0,
                                        WM_APP_SERVICE_STATE_CHANGED,
                                        0,
                                        0,
                                    );
                                    true
                                },
                            ) {
                                Ok(()) => break,
                                Err(e) => {
                                    warn!("SCM watcher error (restarting): {}", e);
                                    std::thread::sleep(std::time::Duration::from_millis(200));
                                    if !scm_cancel_worker.is_cancelled() {
                                        unsafe {
                                            let _ = PostMessageW(
                                                target_hwnd.0,
                                                WM_APP_SERVICE_STATE_CHANGED,
                                                0,
                                                0,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }) {
                    Ok(join) => {
                        self.scm_cancel = Some(scm_cancel);
                        self.scm_watcher_thread = Some(join);
                    }
                    Err(e) => {
                        warn!("Failed to spawn SCM watcher thread: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to initialize ScmWatchCancel: {}", e);
            }
        }
    }

    /// Signals and joins all event-driven background watchers cleanly.
    pub fn stop_watchers(&mut self) {
        if let Some(ref scm_cancel) = self.scm_cancel {
            scm_cancel.cancel();
        }
        if let Some(dir_cancel) = self.dir_cancel {
            unsafe {
                SetEvent(dir_cancel.0);
            }
        }

        if let Some(join) = self.scm_watcher_thread.take() {
            let _ = join.join();
        }
        self.scm_cancel = None;

        if let Some(join) = self.dir_watcher_thread.take() {
            let _ = join.join();
        }
        if let Some(dir_cancel) = self.dir_cancel.take() {
            unsafe {
                CloseHandle(dir_cancel.0);
            }
        }
    }

    /// Handles the `WM_RAISE_MSG` message to bring the window to the foreground.
    pub fn on_raise(&mut self) {
        if self.hwnd.is_null() {
            return;
        }

        unsafe {
            let was_hidden = IsWindowVisible(self.hwnd) == 0;
            if was_hidden {
                // Switch to default tab (Tunnels) when restored from hidden tray
                self.select_tab(TAB_INDEX_TUNNELS);
                ShowWindow(self.hwnd, SW_SHOW);
            }
            if IsIconic(self.hwnd) != 0 {
                ShowWindow(self.hwnd, SW_RESTORE);
            }
            crate::raise::raise(self.hwnd);
        }
    }

    /// Displays the standard About WireGuard dialog.
    pub fn on_about(&self) {
        crate::aboutdialog::run_about_dialog(self.hwnd);
    }

    /// Cleans up resources on destruction.
    pub fn on_destroy(&mut self) {
        self.stop_watchers();
        if self.log_timer_active && !self.hwnd.is_null() {
            unsafe {
                KillTimer(self.hwnd, IDT_LOG_TIMER);
            }
            self.log_timer_active = false;
        }
        if let Some(mut tray) = self.tray.take() {
            tray.dispose();
        }
        if !self.hfont.is_null() {
            unsafe {
                DeleteObject(self.hfont as _);
            }
            self.hfont = ptr::null_mut();
        }
    }
}

/// Runs the cancelable `FindFirstChangeNotificationW` loop watching `dir` for config changes.
fn run_config_dir_watcher(hwnd: SendHwnd, dir: PathBuf, cancel_event: SendHandle) {
    let dir_str = dir.to_string_lossy();
    let watch_filter = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_CREATION;

    let mut dir_wide: Vec<u16> = Vec::new();
    crate::win32_util::encode_wide_null_into(dir_str.as_ref(), &mut dir_wide);

    loop {
        let change_handle = unsafe { FindFirstChangeNotificationW(dir_wide.as_ptr(), 0, watch_filter) };
        if change_handle == INVALID_HANDLE_VALUE || change_handle.is_null() {
            let wait = unsafe { WaitForSingleObject(cancel_event.0, 5000) };
            if wait == WAIT_OBJECT_0 {
                return;
            }
            continue;
        }

        let handles = [cancel_event.0, change_handle];
        loop {
            let wait = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE) };
            if wait == WAIT_OBJECT_0 {
                unsafe {
                    FindCloseChangeNotification(change_handle);
                }
                return;
            }
            if wait != WAIT_OBJECT_0 + 1 {
                break;
            }

            if unsafe { FindNextChangeNotification(change_handle) } == 0 {
                break;
            }

            // Coalesce multi-event file writes (create + write + rename) without busy-polling.
            if unsafe { WaitForSingleObject(cancel_event.0, 75) } == WAIT_OBJECT_0 {
                unsafe {
                    FindCloseChangeNotification(change_handle);
                }
                return;
            }
            for _ in 0..16 {
                if unsafe { WaitForSingleObject(change_handle, 0) } != WAIT_OBJECT_0 {
                    break;
                }
                if unsafe { FindNextChangeNotification(change_handle) } == 0 {
                    break;
                }
            }

            unsafe {
                let _ = PostMessageW(hwnd.0, WM_APP_CONFIGS_CHANGED, 0, 0);
            }
        }

        unsafe {
            FindCloseChangeNotification(change_handle);
        }
        if unsafe { WaitForSingleObject(cancel_event.0, 1000) } == WAIT_OBJECT_0 {
            return;
        }
    }
}

impl Drop for ManageTunnelsWindow {
    fn drop(&mut self) {
        self.on_destroy();
        if !self.hwnd.is_null() {
            unsafe {
                SetWindowLongPtrW(self.hwnd, GWLP_USERDATA, 0);
            }
        }
    }
}

/// Retrieves a mutable reference to the `ManageTunnelsWindow` associated with `hwnd`.
pub unsafe fn from_hwnd<'a>(hwnd: HWND) -> Option<&'a mut ManageTunnelsWindow> {
    if hwnd.is_null() {
        return None;
    }
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ManageTunnelsWindow;
    if ptr.is_null() {
        None
    } else {
        Some(&mut *ptr)
    }
}

/// Win32 Window Procedure for the main WireGuard Manage Tunnels window.
pub unsafe extern "system" fn manage_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let window_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ManageTunnelsWindow;

    match msg {
        WM_NCCREATE => {
            let cs = lparam as *const windows_sys::Win32::UI::WindowsAndMessaging::CREATESTRUCTW;
            if !cs.is_null() {
                let ptr = (*cs).lpCreateParams as *mut ManageTunnelsWindow;
                if !ptr.is_null() {
                    (*ptr).hwnd = hwnd;
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, ptr as isize);
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }

        WM_CREATE => {
            let window_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ManageTunnelsWindow;
            if !window_ptr.is_null() {
                (*window_ptr).setup_ui(hwnd);
            }
            0
        }

        WM_SIZE => {
            let width = (lparam & 0xFFFF) as i32;
            let height = ((lparam >> 16) & 0xFFFF) as i32;
            if !window_ptr.is_null() {
                if wparam == SIZE_MINIMIZED as WPARAM {
                    if (*window_ptr).tray_active {
                        (*window_ptr).hide();
                    } else {
                        (*window_ptr).update_log_timer_and_visibility(Some(false));
                    }
                } else {
                    (*window_ptr).on_size(width, height);
                    (*window_ptr).update_log_timer_and_visibility(None);
                }
            }
            0
        }

        WM_SHOWWINDOW => {
            if !window_ptr.is_null() && lparam == 0 {
                (*window_ptr).update_log_timer_and_visibility(Some(wparam != 0));
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }

        WM_GETMINMAXINFO => {
            let mmi = lparam as *mut MINMAXINFO;
            if !mmi.is_null() {
                (*mmi).ptMinTrackSize.x = MIN_WIDTH;
                (*mmi).ptMinTrackSize.y = MIN_HEIGHT;
            }
            0
        }

        WM_NOTIFY => {
            let nmhdr = lparam as *const NMHDR;
            if !nmhdr.is_null() && !window_ptr.is_null() {
                if (*nmhdr).hwndFrom == (*window_ptr).hwnd_tab && (*nmhdr).code == TCN_SELCHANGE {
                    (*window_ptr).on_tab_change();
                }
            }
            0
        }

        WM_TIMER => {
            if !window_ptr.is_null() {
                (*window_ptr).on_timer(wparam as usize);
            }
            0
        }

        WM_CLOSE => {
            if !window_ptr.is_null() && (*window_ptr).tray_active {
                // "Close to tray" instead of exiting application
                (*window_ptr).hide();
            } else {
                DestroyWindow(hwnd);
            }
            0
        }

        WM_DESTROY => {
            if !window_ptr.is_null() {
                (*window_ptr).on_destroy();
            }
            PostQuitMessage(0);
            0
        }

        WM_NCDESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }

        WM_SYSCOMMAND => {
            let cmd = (wparam & 0xFFF0) as u32;
            if cmd == SC_MINIMIZE && !window_ptr.is_null() && (*window_ptr).tray_active {
                (*window_ptr).hide();
                0
            } else if cmd == IDM_ABOUT_WIREGUARD || wparam as u32 == IDM_ABOUT_WIREGUARD {
                if !window_ptr.is_null() {
                    (*window_ptr).on_about();
                }
                0
            } else {
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
        }

        WM_COMMAND => {
            let cmd = wparam as usize;
            if !window_ptr.is_null() {
                if let Some(mut tray) = (*window_ptr).tray.take() {
                    tray.handle_menu_command(cmd);
                    if (*window_ptr).tray.is_none() {
                        (*window_ptr).tray = Some(tray);
                    }
                }
            }
            0
        }

        WM_QUERYENDSESSION => {
            TRUE as LRESULT
        }

        WM_ENDSESSION => {
            if wparam != 0 {
                if !window_ptr.is_null() {
                    (*window_ptr).on_destroy();
                }
                PostQuitMessage(0);
            }
            0
        }

        msg if msg == WM_RAISE_MSG => {
            if !window_ptr.is_null() {
                (*window_ptr).on_raise();
            }
            0
        }

        msg if msg == WM_TRAY_CALLBACK => {
            if !window_ptr.is_null() {
                if let Some(mut tray) = (*window_ptr).tray.take() {
                    tray.handle_tray_message(lparam as isize);
                    if (*window_ptr).tray.is_none() {
                        (*window_ptr).tray = Some(tray);
                    }
                }
            }
            0
        }

        msg if msg == WM_APP_CONFIGS_CHANGED => {
            if !window_ptr.is_null() {
                (*window_ptr).on_configs_changed();
            }
            0
        }

        msg if msg == WM_APP_SERVICE_STATE_CHANGED => {
            if !window_ptr.is_null() {
                (*window_ptr).on_service_state_changed();
            }
            0
        }

        msg if msg == WM_APP_TRAY_SYNC => {
            if !window_ptr.is_null() {
                (*window_ptr).sync_tray_state();
            }
            0
        }

        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Sets up the main window, system tray, and runs the Win32 message loop.
///
/// Faithfully ported from `RunUI()` in `wireguard-windows/ui/ui.go`.
pub fn run_ui() -> Result<(), Box<dyn std::error::Error>> {
    run_ui_internal(true)
}

/// Sets up the main window in tray-only mode (window initially hidden) and runs the Win32 message loop.
pub fn run_ui_tray() -> Result<(), Box<dyn std::error::Error>> {
    run_ui_internal(false)
}

fn run_ui_internal(show_window: bool) -> Result<(), Box<dyn std::error::Error>> {
    log_to_file(&format!("run_ui_internal(show_window={}): starting WireGuard Windows UI", show_window));
    info!("Starting WireGuard Windows UI (100% Rust)...");

    // Disable process priority boost for consistent desktop responsiveness
    unsafe {
        SetProcessPriorityBoost(GetCurrentProcess(), 1);
    }

    // 1. Create Manage Tunnels window
    log_to_file("run_ui(): calling ManageTunnelsWindow::new()...");
    let mut mtw = ManageTunnelsWindow::new()?;
    log_to_file(&format!("run_ui(): ManageTunnelsWindow ready, HWND={:?}", mtw.hwnd));

    // 2. Initialize and sync System Tray before entering the message loop (even when hidden)
    let hwnd = mtw.hwnd;
    log_to_file("run_ui(): initializing Tray...");
    match crate::tray::Tray::new(hwnd) {
        Ok(mut tray) => {
            tray.set_on_manage(move || unsafe {
                if let Some(win) = from_hwnd(hwnd) {
                    win.update_log_timer_and_visibility(Some(true));
                }
            });
            tray.set_on_import(move || unsafe {
                if let Some(win) = from_hwnd(hwnd) {
                    if let Some(ref mut page) = win.tunnels_page {
                        page.trigger_import_tunnel();
                    }
                    let _ = PostMessageW(hwnd, WM_APP_TRAY_SYNC, 0, 0);
                }
            });
            tray.set_on_tunnel_toggle(move |name, _active| unsafe {
                if let Some(win) = from_hwnd(hwnd) {
                    if let Some(ref mut page) = win.tunnels_page {
                        page.toggle_tunnel_by_name(name);
                    }
                    let _ = PostMessageW(hwnd, WM_APP_TRAY_SYNC, 0, 0);
                }
            });
            tray.set_on_about(move || unsafe {
                PostMessageW(hwnd, WM_SYSCOMMAND, IDM_ABOUT_WIREGUARD as WPARAM, 0);
            });
            tray.set_on_exit(move || unsafe {
                PostQuitMessage(0);
            });
            mtw.tray = Some(tray);
            mtw.tray_active = true;
            mtw.sync_tray_state();
            log_to_file("run_ui(): system tray icon installed successfully");
            info!("System tray icon installed successfully");
        }
        Err(e) => {
            log_to_file(&format!("run_ui(): system tray install failed: {}, continuing in window mode", e));
            warn!(
                "Unable to create tray icon: {}. Continuing with direct window mode.",
                e
            );
            mtw.tray_active = false;
        }
    }

    // 3. Start event-driven background watchers (Configurations dir + SCM services)
    mtw.start_watchers();

    // 4. Show window only if show_window is true (otherwise stay genuinely hidden in tray)
    if show_window {
        log_to_file("run_ui(): calling mtw.show() and mtw.raise()...");
        mtw.show();
        mtw.raise();
        log_to_file("run_ui(): mtw.show() and mtw.raise() done");
    } else {
        log_to_file("run_ui(): tray-only mode (window hidden in tray)");
    }

    // 5. Standard Win32 Message Loop
    log_to_file("run_ui(): entering Win32 message loop");
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    loop {
        let ret = unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) };
        if ret <= 0 {
            log_to_file(&format!("run_ui(): message loop exit with ret={}, msg={}", ret, msg.message));
            // ret == 0 indicates WM_QUIT, negative indicates error
            break;
        }

        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // 6. Deterministic cleanup on exit
    mtw.stop_watchers();
    if let Some(mut tray) = mtw.tray.take() {
        tray.dispose();
    }

    log_to_file(&format!("run_ui(): finished message loop with wParam={}", msg.wParam));
    info!(
        "WireGuard UI exited message loop with exit code {}",
        msg.wParam
    );
    Ok(())
}
