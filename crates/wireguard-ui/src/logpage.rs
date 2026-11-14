// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Native Win32 Log Viewer tab page for WireGuard Windows (100% Rust).
//!
//! Faithful port of `wireguard-windows/ui/logpage.go`.
//! Features:
//! - High-performance Win32 `WC_LISTVIEWW` report table with double buffering and grid lines.
//! - Columns: "Time" (YYYY-MM-DD HH:MM:SS) and "Log Message".
//! - Dynamic live streaming from `wireguard_ringlog` shared memory mapping (or fallback to log file).
//! - Auto-scrolling when viewed at bottom.
//! - Keyboard shortcuts (`Ctrl+C` copy, `Ctrl+A` select all, `Ctrl+S` export).
//! - Right-click context menu.
//! - Copy to Windows Clipboard (`OpenClipboard`, `SetClipboardData`).
//! - Bottom bar with "Save to file…" and "Clear log" buttons.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, Once, OnceLock};
use tracing::{info, warn};

use windows_sys::Win32::Foundation::{
    FALSE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, TRUE, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, GetSysColorBrush, InvalidateRect, SetBkMode,
    COLOR_BTNFACE, FW_NORMAL, HBRUSH, HDC, HFONT, TRANSPARENT,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX, LVCFMT_LEFT, LVCF_FMT,
    LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVIS_SELECTED, LVITEMW,
    LVM_DELETEALLITEMS, LVM_DELETEITEM, LVM_ENSUREVISIBLE, LVM_GETNEXTITEM,
    LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_ISITEMVISIBLE, LVM_SETCOLUMNWIDTH,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMCOUNT, LVM_SETITEMSTATE, LVM_SETITEMTEXTW,
    LVNI_SELECTED, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_EX_GRIDLINES, LVS_REPORT,
    LVS_SHOWSELALWAYS, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CONTROL};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CallWindowProcW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DestroyWindow, GetCursorPos, GetParent, GetWindowLongPtrW,
    LoadCursorW, MoveWindow, RegisterClassExW, SendMessageW, SetWindowLongPtrW,
    TrackPopupMenu, BS_PUSHBUTTON, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA,
    GWLP_WNDPROC, IDC_ARROW, MF_SEPARATOR, MF_STRING, TPM_LEFTALIGN, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, WM_COMMAND, WM_CONTEXTMENU, WM_CTLCOLORSTATIC, WM_KEYDOWN,
    WM_RBUTTONUP, WM_SETFONT, WM_SETREDRAW, WNDCLASSEXW, WNDPROC, WS_BORDER, WS_CHILD,
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_HSCROLL, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

use crate::filesave::select_save_log_path;
use crate::win32_util::{encode_wide_null_into, with_wide_null};
use wireguard_ringlog::{RingLogger, CURSOR_ALL};

/// Window class name for the LogPage container window.
const LOG_PAGE_CONTAINER_CLASS: &str = "WireGuardLogPageContainer";

/// Control IDs for child controls.
const ID_LIST_LOGS: usize = 2001;
const ID_BTN_SAVE: usize = 2002;
const ID_BTN_CLEAR: usize = 2003;

/// Context menu command IDs.
const ID_MENU_COPY: usize = 2101;
const ID_MENU_SELECT_ALL: usize = 2102;
const ID_MENU_SAVE: usize = 2103;
const ID_MENU_CLEAR: usize = 2104;

/// Windows Clipboard format for Unicode text (CF_UNICODETEXT = 13).
const CF_UNICODETEXT: u32 = 13;

/// `LVM_FIRST + 50`: retrieves the number of selected items in a ListView control.
const LVM_GETSELECTEDCOUNT: u32 = 0x1000 + 50;

/// Maximum number of log lines kept in memory matching Go's `maxLogLinesDisplayed = 10000`.
const MAX_LOG_LINES_DISPLAYED: usize = 10_000;

/// Column widths.
const COLUMN_TIME_WIDTH: i32 = 160;

/// Error types for `LogPage` operations.
#[derive(Debug, thiserror::Error)]
pub enum LogPageError {
    #[error("Win32 error: {0}")]
    Win32(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Ringlog error: {0}")]
    Ringlog(#[from] wireguard_ringlog::RinglogError),
}

pub type Result<T> = std::result::Result<T, LogPageError>;

/// In-memory representation of an individual displayed log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogItem {
    pub timestamp: String,
    pub message: String,
}

static PENDING_UI_LOGS: OnceLock<Mutex<Vec<LogItem>>> = OnceLock::new();

fn pending_ui_logs() -> &'static Mutex<Vec<LogItem>> {
    PENDING_UI_LOGS.get_or_init(|| Mutex::new(Vec::with_capacity(64)))
}

/// Formats the current UTC/local timestamp as `YYYY-MM-DD HH:MM:SS` and queues a UI log entry
/// so it immediately appears in the Log tab.
pub fn append_ui_log_line(msg: &str) {
    let ns = wireguard_ringlog::current_unix_nanos();
    let ts = wireguard_ringlog::format_timestamp_sec(ns);
    if let Ok(mut guard) = pending_ui_logs().lock() {
        if guard.len() < 1024 {
            guard.push(LogItem {
                timestamp: ts,
                message: format!("[UI] {msg}"),
            });
        }
    }
}

/// The Win32 Log Viewer tab page component.
pub struct LogPage {
    inner: Box<LogPageInner>,
}

struct LogPageInner {
    hwnd_container: HWND,
    hwnd_list: HWND,
    hwnd_btn_save: HWND,
    hwnd_btn_clear: HWND,
    old_list_wndproc: WNDPROC,
    logger: Option<RingLogger>,
    cursor: u32,
    loaded: bool,
    last_next_index: Option<u32>,
    items: Vec<LogItem>,
    font: HFONT,
    scratch_wide: Vec<u16>,
}

/// Registers the Win32 window class for the LogPage container once.
fn register_log_page_class(h_instance: HINSTANCE) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        with_wide_null(LOG_PAGE_CONTAINER_CLASS, |class_ptr| {
            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(log_page_container_wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: h_instance,
                hIcon: std::ptr::null_mut(),
                hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
                hbrBackground: (COLOR_BTNFACE + 1) as usize as HBRUSH,
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_ptr,
                hIconSm: std::ptr::null_mut(),
            };
            unsafe {
                RegisterClassExW(&wnd_class);
            }
        });
    });
}

/// Initializes common controls for the ListView.
fn init_list_common_controls() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let iccx = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        unsafe {
            InitCommonControlsEx(&iccx);
        }
    });
}

impl LogPage {
    /// Creates a new Win32 Log Viewer page within `parent` positioned at `rect`.
    /// Log history is loaded lazily on first visibility via `on_visibility_changed(true)`.
    pub fn new(parent: HWND, rect: RECT) -> Result<Self> {
        let h_instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        register_log_page_class(h_instance);
        init_list_common_controls();

        let width = (rect.right - rect.left).max(100);
        let height = (rect.bottom - rect.top).max(100);

        let hwnd_container = with_wide_null(LOG_PAGE_CONTAINER_CLASS, |class_ptr| {
            with_wide_null("", |title_ptr| unsafe {
                CreateWindowExW(
                    0,
                    class_ptr,
                    title_ptr,
                    WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                    rect.left,
                    rect.top,
                    width,
                    height,
                    parent,
                    std::ptr::null_mut(),
                    h_instance,
                    std::ptr::null(),
                )
            })
        });

        if hwnd_container.is_null() {
            return Err(LogPageError::Win32(
                "Failed to create LogPage container window".into(),
            ));
        }

        // Create standard GUI font (Segoe UI, 9pt)
        let font = with_wide_null("Segoe UI", |font_ptr| unsafe {
            CreateFontW(
                15,
                0,
                0,
                0,
                FW_NORMAL as i32,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                font_ptr,
            )
        });

        // Create Report-style ListView control
        let hwnd_list = unsafe {
            CreateWindowExW(
                0,
                WC_LISTVIEWW,
                std::ptr::null(),
                WS_CHILD
                    | WS_VISIBLE
                    | WS_BORDER
                    | WS_VSCROLL
                    | WS_HSCROLL
                    | WS_TABSTOP
                    | LVS_REPORT
                    | LVS_SHOWSELALWAYS,
                0,
                0,
                width,
                height - 36,
                hwnd_container,
                ID_LIST_LOGS as _,
                h_instance,
                std::ptr::null(),
            )
        };

        if hwnd_list.is_null() {
            unsafe {
                DestroyWindow(hwnd_container);
            }
            return Err(LogPageError::Win32("Failed to create ListView control".into()));
        }

        // Apply extended styles: Full row select, double buffering, grid lines
        unsafe {
            SendMessageW(
                hwnd_list,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES) as WPARAM,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES) as LPARAM,
            );
            if !font.is_null() {
                SendMessageW(hwnd_list, WM_SETFONT, font as WPARAM, 1);
            }
        }

        // Setup columns: "Time" (col 0) and "Log message" (col 1)
        with_wide_null("Time", |title_ptr| unsafe {
            let mut col_time: LVCOLUMNW = std::mem::zeroed();
            col_time.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
            col_time.fmt = LVCFMT_LEFT as i32;
            col_time.cx = COLUMN_TIME_WIDTH;
            col_time.pszText = title_ptr as *mut u16;
            col_time.iSubItem = 0;
            SendMessageW(
                hwnd_list,
                LVM_INSERTCOLUMNW,
                0,
                &col_time as *const _ as LPARAM,
            );
        });

        with_wide_null("Log message", |title_ptr| unsafe {
            let mut col_msg: LVCOLUMNW = std::mem::zeroed();
            col_msg.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
            col_msg.fmt = LVCFMT_LEFT as i32;
            col_msg.cx = (width - COLUMN_TIME_WIDTH - 24).max(200);
            col_msg.pszText = title_ptr as *mut u16;
            col_msg.iSubItem = 1;
            SendMessageW(
                hwnd_list,
                LVM_INSERTCOLUMNW,
                1,
                &col_msg as *const _ as LPARAM,
            );
        });

        // Create bottom bar buttons: "Save to file…" and "Clear log"
        let (hwnd_btn_save, hwnd_btn_clear) = with_wide_null("BUTTON", |btn_ptr| {
            let save = with_wide_null("Save to file…", |save_ptr| unsafe {
                CreateWindowExW(
                    0,
                    btn_ptr,
                    save_ptr,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                    width - 215,
                    height - 30,
                    110,
                    26,
                    hwnd_container,
                    ID_BTN_SAVE as _,
                    h_instance,
                    std::ptr::null(),
                )
            });
            if !save.is_null() && !font.is_null() {
                unsafe {
                    SendMessageW(save, WM_SETFONT, font as WPARAM, 1);
                }
            }

            let clear = with_wide_null("Clear log", |clear_ptr| unsafe {
                CreateWindowExW(
                    0,
                    btn_ptr,
                    clear_ptr,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                    width - 95,
                    height - 30,
                    90,
                    26,
                    hwnd_container,
                    ID_BTN_CLEAR as _,
                    h_instance,
                    std::ptr::null(),
                )
            });
            if !clear.is_null() && !font.is_null() {
                unsafe {
                    SendMessageW(clear, WM_SETFONT, font as WPARAM, 1);
                }
            }

            (save, clear)
        });

        let mut inner = Box::new(LogPageInner {
            hwnd_container,
            hwnd_list,
            hwnd_btn_save,
            hwnd_btn_clear,
            old_list_wndproc: None,
            logger: None,
            cursor: CURSOR_ALL,
            loaded: false,
            last_next_index: None,
            items: Vec::new(),
            font,
            scratch_wide: Vec::new(),
        });

        // Attach self to container's GWLP_USERDATA BEFORE subclassing or sending ListView messages!
        let raw = &mut *inner as *mut LogPageInner;
        unsafe {
            SetWindowLongPtrW(hwnd_container, GWLP_USERDATA, raw as isize);
        }

        // Subclass ListView to intercept keyboard shortcuts and context menu
        let old_list_wndproc = unsafe {
            let proc = SetWindowLongPtrW(
                hwnd_list,
                GWLP_WNDPROC,
                log_list_subclass_proc as *const () as isize,
            );
            std::mem::transmute::<isize, WNDPROC>(proc)
        };
        inner.old_list_wndproc = old_list_wndproc;

        Ok(Self { inner })
    }

    /// Returns the HWND handle of the LogPage container window.
    pub fn hwnd(&self) -> HWND {
        self.inner.hwnd_container
    }

    /// Resizes the LogPage container and recalculates child control positions.
    pub fn resize(&mut self, rect: RECT) {
        self.inner.resize(rect);
    }

    /// Handles visibility / tab-selection transitions and lazily loads log history
    /// when the Log tab is first shown.
    pub fn on_visibility_changed(&mut self, visible: bool) {
        self.inner.on_visibility_changed(visible);
    }

    /// Returns `true` if the listview is scrolled near or at the bottom.
    pub fn is_at_bottom(&self) -> bool {
        self.inner.is_at_bottom()
    }

    /// Scrolls the ListView to make the last item visible.
    pub fn scroll_to_bottom(&self) {
        self.inner.scroll_to_bottom();
    }

    /// Polls new log lines from the ringlogger shared memory buffer and updates the table.
    pub fn poll_new_logs(&mut self) {
        self.inner.poll_new_logs();
    }

    pub fn on_copy(&self) {
        self.inner.on_copy();
    }

    pub fn on_select_all(&self) {
        self.inner.on_select_all();
    }

    pub fn on_save(&self) {
        self.inner.on_save();
    }

    pub fn on_clear(&mut self) {
        self.inner.on_clear();
    }
}

impl LogPageInner {
    /// Resizes the LogPage container and recalculates child control positions.
    pub fn resize(&mut self, rect: RECT) {
        let width = (rect.right - rect.left).max(100);
        let height = (rect.bottom - rect.top).max(100);

        unsafe {
            MoveWindow(self.hwnd_container, rect.left, rect.top, width, height, TRUE);
        }

        let btn_h = 26;
        let pad_b = 6;
        let list_h = (height - btn_h - pad_b * 2).max(50);

        unsafe {
            MoveWindow(self.hwnd_list, 0, 0, width, list_h, TRUE);
        }

        // Stretch Column 1 to fit the remaining width
        let col1_w = (width - COLUMN_TIME_WIDTH - 24).max(200);
        unsafe {
            SendMessageW(self.hwnd_list, LVM_SETCOLUMNWIDTH, 0, COLUMN_TIME_WIDTH as LPARAM);
            SendMessageW(self.hwnd_list, LVM_SETCOLUMNWIDTH, 1, col1_w as LPARAM);
        }

        let btn_y = list_h + pad_b;
        unsafe {
            MoveWindow(self.hwnd_btn_save, width - 215, btn_y, 110, btn_h, TRUE);
            MoveWindow(self.hwnd_btn_clear, width - 95, btn_y, 90, btn_h, TRUE);
        }
    }

    /// Returns true if the ListView is currently scrolled to the bottom (last line visible).
    pub fn is_at_bottom(&self) -> bool {
        let count = self.items.len();
        if count == 0 {
            return true;
        }
        unsafe {
            SendMessageW(
                self.hwnd_list,
                LVM_ISITEMVISIBLE,
                (count - 1) as WPARAM,
                0,
            ) != 0
        }
    }

    /// Scrolls the ListView to make the last item visible.
    pub fn scroll_to_bottom(&self) {
        let count = self.items.len();
        if count > 0 {
            unsafe {
                SendMessageW(
                    self.hwnd_list,
                    LVM_ENSUREVISIBLE,
                    (count - 1) as WPARAM,
                    0,
                );
            }
        }
    }

    /// Lazily loads initial log history on first visibility and polls for updates
    /// whenever the tab becomes visible.
    pub fn on_visibility_changed(&mut self, visible: bool) {
        if !visible {
            return;
        }
        let first_load = !self.loaded;
        self.loaded = true;
        self.poll_new_logs();
        if first_load {
            self.scroll_to_bottom();
        }
    }

    /// Polls new log lines from the ringlogger shared memory buffer and updates the table.
    pub fn poll_new_logs(&mut self) {
        // Attempt reconnection if logger is not yet available
        if self.logger.is_none() {
            self.logger = connect_ringlogger();
        }
        self.loaded = true;

        let logger_has_new = match self.logger.as_ref() {
            Some(logger) => self.last_next_index != Some(logger.next_index()),
            None => false,
        };
        let has_pending_ui = pending_ui_logs()
            .lock()
            .map(|guard| !guard.is_empty())
            .unwrap_or(false);

        // O(1) short-circuit when neither RingLogger index nor pending UI queue changed
        if !logger_has_new && !has_pending_ui {
            return;
        }

        let mut new_items: Vec<LogItem> = Vec::new();

        if logger_has_new {
            if let Some(logger) = &self.logger {
                let next_idx = logger.next_index();
                let (lines, next_cursor) = logger.follow_from_cursor(self.cursor);
                self.cursor = next_cursor;
                self.last_next_index = Some(next_idx);
                if !lines.is_empty() {
                    new_items.reserve(lines.len());
                    for line in lines {
                        new_items.push(LogItem {
                            timestamp: line.formatted_timestamp_sec(),
                            message: line.line,
                        });
                    }
                }
            }
        }

        if has_pending_ui {
            if let Ok(mut pending) = pending_ui_logs().lock() {
                if !pending.is_empty() {
                    new_items.append(&mut *pending);
                }
            }
        }

        if new_items.is_empty() {
            return;
        }

        let was_at_bottom = self.is_at_bottom();

        // Trim any overflow before inserting rows so we never insert and immediately delete excess rows
        let skip = new_items.len().saturating_sub(MAX_LOG_LINES_DISPLAYED);
        let insert_len = new_items.len() - skip;
        let total_after = self.items.len() + insert_len;
        let excess = total_after.saturating_sub(MAX_LOG_LINES_DISPLAYED);

        // Freeze redraw and pre-allocate item count while updating entries for maximum performance
        unsafe {
            SendMessageW(self.hwnd_list, WM_SETREDRAW, FALSE as WPARAM, 0);
        }

        if excess > 0 {
            if excess >= self.items.len() {
                unsafe {
                    SendMessageW(self.hwnd_list, LVM_DELETEALLITEMS, 0, 0);
                }
                self.items.clear();
            } else {
                for _ in 0..excess {
                    unsafe {
                        SendMessageW(self.hwnd_list, LVM_DELETEITEM, 0, 0);
                    }
                }
                self.items.drain(0..excess);
            }
        }

        unsafe {
            SendMessageW(
                self.hwnd_list,
                LVM_SETITEMCOUNT,
                (self.items.len() + insert_len) as WPARAM,
                0,
            );
        }

        for item in new_items.into_iter().skip(skip) {
            self.insert_row(&item);
            self.items.push(item);
        }

        // Re-enable redraw and invalidate
        unsafe {
            SendMessageW(self.hwnd_list, WM_SETREDRAW, TRUE as WPARAM, 0);
            InvalidateRect(self.hwnd_list, std::ptr::null(), TRUE);
        }

        if was_at_bottom {
            self.scroll_to_bottom();
        }
    }

    /// Inserts a single row into the ListView control using a single reusable UTF-16 scratch buffer.
    fn insert_row(&mut self, item: &LogItem) {
        let index = self.items.len() as i32;

        encode_wide_null_into(&item.timestamp, &mut self.scratch_wide);

        let mut lvi: LVITEMW = unsafe { std::mem::zeroed() };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.iSubItem = 0;
        lvi.pszText = self.scratch_wide.as_mut_ptr();

        unsafe {
            SendMessageW(
                self.hwnd_list,
                LVM_INSERTITEMW,
                0,
                &lvi as *const _ as LPARAM,
            );

            encode_wide_null_into(&item.message, &mut self.scratch_wide);
            let mut lvs: LVITEMW = std::mem::zeroed();
            lvs.iSubItem = 1;
            lvs.pszText = self.scratch_wide.as_mut_ptr();
            SendMessageW(
                self.hwnd_list,
                LVM_SETITEMTEXTW,
                index as WPARAM,
                &lvs as *const _ as LPARAM,
            );
        }
    }

    /// Copies selected log rows formatted as `YYYY-MM-DD HH:MM:SS: <message>` to clipboard.
    ///
    /// Matches `(*LogPage).onCopy()` from `logpage.go`.
    pub fn on_copy(&self) {
        let count = self.items.len();
        if count == 0 {
            return;
        }

        let selected_count =
            unsafe { SendMessageW(self.hwnd_list, LVM_GETSELECTEDCOUNT, 0, 0) } as usize;
        if selected_count == 0 {
            return;
        }

        let mut wide = Vec::with_capacity(selected_count.saturating_mul(96).saturating_add(1));
        let mut idx = unsafe {
            SendMessageW(
                self.hwnd_list,
                LVM_GETNEXTITEM,
                usize::MAX,
                LVNI_SELECTED as LPARAM,
            ) as i32
        };

        while idx >= 0 && (idx as usize) < count {
            let item = &self.items[idx as usize];
            wide.extend(item.timestamp.encode_utf16());
            wide.extend(": ".encode_utf16());
            wide.extend(item.message.encode_utf16());
            wide.extend("\r\n".encode_utf16());

            idx = unsafe {
                SendMessageW(
                    self.hwnd_list,
                    LVM_GETNEXTITEM,
                    idx as usize,
                    LVNI_SELECTED as LPARAM,
                ) as i32
            };
        }

        if wide.is_empty() {
            return;
        }
        wide.push(0);

        copy_wide_to_clipboard(self.hwnd_container, &wide);
    }

    /// Selects all log rows in the table.
    ///
    /// Matches `(*LogPage).onSelectAll()` from `logpage.go`.
    pub fn on_select_all(&self) {
        let mut lvi: LVITEMW = unsafe { std::mem::zeroed() };
        lvi.state = LVIS_SELECTED;
        lvi.stateMask = LVIS_SELECTED;
        unsafe {
            SendMessageW(
                self.hwnd_list,
                LVM_SETITEMSTATE,
                usize::MAX,
                &lvi as *const _ as LPARAM,
            );
        }
    }

    /// Opens the Save File dialog and writes all current logs to a `.txt` file.
    ///
    /// Matches `(*LogPage).onSave()` from `logpage.go`.
    pub fn on_save(&self) {
        let file_path = match select_save_log_path(self.hwnd_container) {
            Some(p) => p,
            None => return,
        };

        let mut file = match fs::File::create(&file_path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to create log export file {:?}: {}", file_path, e);
                return;
            }
        };

        // If ringlogger mapping is active, dump directly to file
        if let Some(logger) = &self.logger {
            if let Err(e) = logger.write_to(&mut file) {
                warn!("logger.write_to failed: {}, falling back to buffer", e);
                for item in &self.items {
                    let _ = writeln!(file, "{}: {}", item.timestamp, item.message);
                }
            }
        } else {
            for item in &self.items {
                let _ = writeln!(file, "{}: {}", item.timestamp, item.message);
            }
        }

        info!("Exported log messages to {:?}", file_path);
    }

    /// Clears the in-memory displayed log rows.
    pub fn on_clear(&mut self) {
        unsafe {
            SendMessageW(self.hwnd_list, LVM_DELETEALLITEMS, 0, 0);
        }
        self.items.clear();
    }
}

impl Drop for LogPageInner {
    fn drop(&mut self) {
        unsafe {
            if !self.hwnd_container.is_null() {
                SetWindowLongPtrW(self.hwnd_container, GWLP_USERDATA, 0);
            }
            if !self.font.is_null() {
                DeleteObject(self.font);
                self.font = std::ptr::null_mut();
            }
        }
    }
}

/// Copies a NUL-terminated UTF-16 slice directly to the Windows clipboard as `CF_UNICODETEXT`.
fn copy_wide_to_clipboard(hwnd: HWND, wide: &[u16]) {
    let bytes_len = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        if OpenClipboard(hwnd) != 0 {
            EmptyClipboard();
            let h_mem = GlobalAlloc(GMEM_MOVEABLE, bytes_len);
            if !h_mem.is_null() {
                let ptr = GlobalLock(h_mem) as *mut u16;
                if !ptr.is_null() {
                    std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                    GlobalUnlock(h_mem);
                    SetClipboardData(CF_UNICODETEXT, h_mem as _);
                }
            }
            CloseClipboard();
        }
    }
}

/// Connects to the WireGuard ringlogger shared memory mapping or log file.
fn connect_ringlogger() -> Option<RingLogger> {
    // 1. Try opening named shared memory mapping "WireGuardLog"
    if let Ok(logger) = RingLogger::open_named("WireGuardLog", "UI", true) {
        return Some(logger);
    }

    // 2. Fallback path in default installation directory
    let fallback = Path::new(r"C:\Program Files\WireGuard\Data\log.bin");
    if fallback.exists() {
        if let Ok(logger) = RingLogger::open(fallback, "UI") {
            return Some(logger);
        }
    }

    // 3. Try opening under LocalSystem if permissions are restricted
    if let Ok(Some(logger)) = wireguard_elevate::do_as_system(|| {
        if fallback.exists() {
            Ok(RingLogger::open(fallback, "UI").ok())
        } else {
            Ok(None)
        }
    }) {
        return Some(logger);
    }

    None
}

/// Displays the right-click context menu over the ListView.
fn show_log_context_menu(hwnd_list: HWND) {
    let mut pt: POINT = unsafe { std::mem::zeroed() };
    unsafe {
        GetCursorPos(&mut pt);
    }

    let h_menu = unsafe { CreatePopupMenu() };
    if h_menu.is_null() {
        return;
    }

    let parent = unsafe { GetParent(hwnd_list) };
    let page_ptr = unsafe { GetWindowLongPtrW(parent, GWLP_USERDATA) as *mut LogPageInner };
    if page_ptr.is_null() {
        unsafe {
            DestroyMenu(h_menu);
        }
        return;
    }

    let page = unsafe { &mut *page_ptr };

    unsafe {
        for (id, label) in [
            (ID_MENU_COPY, "&Copy\tCtrl+C"),
            (ID_MENU_SELECT_ALL, "Select &all\tCtrl+A"),
        ] {
            with_wide_null(label, |ptr| {
                AppendMenuW(h_menu, MF_STRING, id, ptr);
            });
        }
        AppendMenuW(h_menu, MF_SEPARATOR, 0, std::ptr::null());
        for (id, label) in [
            (ID_MENU_SAVE, "&Save to file…\tCtrl+S"),
            (ID_MENU_CLEAR, "Clear &log"),
        ] {
            with_wide_null(label, |ptr| {
                AppendMenuW(h_menu, MF_STRING, id, ptr);
            });
        }

        let cmd = TrackPopupMenu(
            h_menu,
            TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
            pt.x,
            pt.y,
            0,
            hwnd_list,
            std::ptr::null(),
        ) as usize;

        DestroyMenu(h_menu);

        match cmd {
            ID_MENU_COPY => page.on_copy(),
            ID_MENU_SELECT_ALL => page.on_select_all(),
            ID_MENU_SAVE => page.on_save(),
            ID_MENU_CLEAR => page.on_clear(),
            _ => {}
        }
    }
}

/// Subclass window procedure for the ListView to handle shortcuts and context menu.
unsafe extern "system" fn log_list_subclass_proc(
    hwnd: HWND,
    msg: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    let parent = GetParent(hwnd);
    let page_ptr = GetWindowLongPtrW(parent, GWLP_USERDATA) as *mut LogPageInner;

    match msg {
        WM_KEYDOWN => {
            if !page_ptr.is_null() {
                let page = &mut *page_ptr;
                let ctrl_down = (GetKeyState(VK_CONTROL as i32) as u16 & 0x8000) != 0;

                if ctrl_down {
                    match w_param as u8 {
                        b'C' | b'c' => {
                            page.on_copy();
                            return 0;
                        }
                        b'A' | b'a' => {
                            page.on_select_all();
                            return 0;
                        }
                        b'S' | b's' => {
                            page.on_save();
                            return 0;
                        }
                        _ => {}
                    }
                }
            }
        }

        WM_RBUTTONUP | WM_CONTEXTMENU => {
            show_log_context_menu(hwnd);
            return 0;
        }

        _ => {}
    }

    let old_proc = if !page_ptr.is_null() {
        (*page_ptr).old_list_wndproc
    } else {
        None
    };

    if old_proc.is_some() {
        CallWindowProcW(old_proc, hwnd, msg, w_param, l_param)
    } else {
        DefWindowProcW(hwnd, msg, w_param, l_param)
    }
}

/// Container window procedure handling background color and button clicks.
unsafe extern "system" fn log_page_container_wndproc(
    hwnd: HWND,
    msg: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    let page_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut LogPageInner;

    match msg {
        WM_CTLCOLORSTATIC => {
            let hdc = w_param as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            GetSysColorBrush(COLOR_BTNFACE) as LRESULT
        }

        WM_COMMAND => {
            let ctrl_id = (w_param & 0xFFFF) as usize;
            if !page_ptr.is_null() {
                let page = &mut *page_ptr;
                match ctrl_id {
                    ID_BTN_SAVE => {
                        page.on_save();
                        return 0;
                    }
                    ID_BTN_CLEAR => {
                        page.on_clear();
                        return 0;
                    }
                    _ => {}
                }
            }
            0
        }

        _ => DefWindowProcW(hwnd, msg, w_param, l_param),
    }
}
