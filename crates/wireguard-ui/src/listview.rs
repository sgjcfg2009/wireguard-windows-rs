// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Native Win32 ListView control wrapper for the WireGuard tunnel list.
//!
//! Provides a report-view list control with double buffering, customized state
//! icons (active, inactive, activating, deactivating), natural sort ordering,
//! and selection event handling matching `wireguard-windows/ui/listview.go`.

use std::ptr;

use windows_sys::Win32::Foundation::{FALSE, HWND, LPARAM, RECT, TRUE, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen, CreateSolidBrush,
    DeleteDC, DeleteObject, Ellipse, FillRect, GetDC, GetSysColorBrush, InvalidateRect,
    ReleaseDC, SelectObject, UpdateWindow, COLOR_WINDOW, HBITMAP, HFONT, HGDIOBJ, PS_SOLID,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    ImageList_Add, ImageList_Create, ImageList_Destroy, InitCommonControlsEx, HIMAGELIST,
    ICC_LISTVIEW_CLASSES, ILC_COLOR32, INITCOMMONCONTROLSEX, LVCFMT_LEFT, LVCF_FMT, LVCF_SUBITEM,
    LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_IMAGE, LVIF_PARAM, LVIF_STATE, LVIF_TEXT, LVIS_FOCUSED,
    LVIS_SELECTED, LVITEMW, LVM_DELETEALLITEMS, LVM_DELETEITEM, LVM_ENSUREVISIBLE, LVM_GETNEXTITEM,
    LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_REDRAWITEMS, LVM_SETCOLUMNWIDTH,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETIMAGELIST, LVM_SETITEMSTATE, LVM_SETITEMW, LVNI_SELECTED,
    LVSIL_SMALL,
    LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_NOCOLUMNHEADER, LVS_REPORT, LVS_SHOWSELALWAYS,
    LVS_SINGLESEL, NMHDR, NMLISTVIEW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, MoveWindow, SendMessageW, WM_SETFONT, WM_SETREDRAW,
    WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_TABSTOP, WS_VISIBLE,
};

use wireguard_conf::tunnel_name_is_less;
pub use wireguard_types::TunnelState;
use crate::log_to_file;
use crate::win32_util::{encode_wide_null_into, with_wide_null};

/// Common control notification codes computed without overflow.
const LVN_FIRST: u32 = 0u32.wrapping_sub(100);
const LVN_ITEMCHANGED_CODE: u32 = LVN_FIRST.wrapping_sub(1);
const LVN_ITEMACTIVATE_CODE: u32 = LVN_FIRST.wrapping_sub(14);
const NM_DBLCLK_CODE: u32 = 0u32.wrapping_sub(3);
const NM_RETURN_CODE: u32 = 0u32.wrapping_sub(4);

/// Color representations for the tunnel state icons (BGR format for Win32 GDI).
const COLOR_STATE_STOPPED: u32 = 0x009E9E9E; // Gray
const COLOR_STATE_STARTED: u32 = 0x002E7D32; // Green
const COLOR_STATE_STARTING: u32 = 0x0000B0FF; // Amber / Light Blue
const COLOR_STATE_STOPPING: u32 = 0x001E51E6; // Orange (RGB 230, 81, 30)
const COLOR_STATE_UNKNOWN: u32 = 0x0078909C; // Slate Gray

/// ImageList icon indices for the tunnel operational states.
pub const ICON_INDEX_STOPPED: i32 = 0;
pub const ICON_INDEX_STARTED: i32 = 1;
pub const ICON_INDEX_STARTING: i32 = 2;
pub const ICON_INDEX_STOPPING: i32 = 3;
pub const ICON_INDEX_UNKNOWN: i32 = 4;

/// Maps a `TunnelState` to its corresponding icon index in the `ImageList`.
pub fn state_to_icon_index(state: TunnelState) -> i32 {
    match state {
        TunnelState::Stopped => ICON_INDEX_STOPPED,
        TunnelState::Started => ICON_INDEX_STARTED,
        TunnelState::Starting => ICON_INDEX_STARTING,
        TunnelState::Stopping => ICON_INDEX_STOPPING,
        TunnelState::Unknown => ICON_INDEX_UNKNOWN,
    }
}

/// Represents a tunnel entry displayed in the list view.
#[derive(Debug, Clone)]
pub struct TunnelItem {
    pub name: String,
    pub svc_name_wide: Vec<u16>,
    pub state: TunnelState,
}

impl PartialEq for TunnelItem {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.state == other.state
    }
}

impl Eq for TunnelItem {}

impl TunnelItem {
    pub fn new(name: impl Into<String>, state: TunnelState) -> Self {
        const PREFIX: &str = "WireGuardTunnel$";
        let name = name.into();
        let mut svc_name_wide = Vec::with_capacity(PREFIX.len() + name.len() + 1);
        svc_name_wide.extend(PREFIX.encode_utf16());
        svc_name_wide.extend(name.encode_utf16());
        svc_name_wide.push(0);
        Self {
            name,
            svc_name_wide,
            state,
        }
    }
}

/// Notifications triggered by the list view that can be handled by the parent container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListViewNotification {
    /// Item selection changed to the specified tunnel (or None if deselected).
    SelectionChanged(Option<String>),
    /// Item activated via double click or Enter key.
    ItemActivated(String),
}

/// Strict total ordering for sorted tunnel diffing and natural display order.
fn cmp_tunnel_name(a: &str, b: &str) -> std::cmp::Ordering {
    if tunnel_name_is_less(a, b) {
        std::cmp::Ordering::Less
    } else if tunnel_name_is_less(b, a) {
        std::cmp::Ordering::Greater
    } else {
        a.cmp(b)
    }
}

/// Native Win32 ListView wrapper for displaying WireGuard tunnels.
pub struct TunnelListView {
    hwnd: HWND,
    image_list: HIMAGELIST,
    font: HFONT,
    tunnels: Vec<TunnelItem>,
    scratch_wide: Vec<u16>,
    is_syncing: bool,
}

impl TunnelListView {
    /// Creates a new `TunnelListView` control attached to `parent`.
    pub fn new(parent: HWND, x: i32, y: i32, width: i32, height: i32) -> Result<Self, String> {
        log_to_file("TunnelListView::new(): initializing common controls");
        // Ensure common controls are initialized for ListView
        let mut icex = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        unsafe {
            InitCommonControlsEx(&mut icex);
        }

        let hinstance = unsafe { GetModuleHandleW(ptr::null()) };

        // Create the native ListView control with report style and no column header
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | WS_BORDER
            | WS_CLIPCHILDREN
            | WS_CLIPSIBLINGS
            | LVS_REPORT
            | LVS_NOCOLUMNHEADER
            | LVS_SINGLESEL
            | LVS_SHOWSELALWAYS;

        log_to_file("TunnelListView::new(): calling CreateWindowExW for SysListView32");
        let hwnd = with_wide_null("SysListView32", |class_ptr| unsafe {
            CreateWindowExW(
                0,
                class_ptr,
                ptr::null(),
                style,
                x,
                y,
                width,
                height,
                parent,
                ptr::null_mut(),
                hinstance,
                ptr::null(),
            )
        });

        if hwnd.is_null() {
            log_to_file("TunnelListView::new(): CreateWindowExW failed");
            return Err("Failed to create SysListView32 window".to_string());
        }
        log_to_file(&format!("TunnelListView::new(): SysListView32 created, HWND={:?}", hwnd));

        // Enable double buffering and full row selection
        let ex_style = LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT;
        unsafe {
            SendMessageW(
                hwnd,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                ex_style as WPARAM,
                ex_style as LPARAM,
            );
        }

        // Insert primary column (stretched across width)
        with_wide_null("Tunnel", |title_ptr| unsafe {
            let mut col: LVCOLUMNW = std::mem::zeroed();
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
            col.fmt = LVCFMT_LEFT;
            col.cx = width.max(180);
            col.pszText = title_ptr as *mut u16;
            SendMessageW(hwnd, LVM_INSERTCOLUMNW, 0, &col as *const _ as LPARAM);
        });

        // Create standard Segoe UI font for high-DPI modern look
        let font = with_wide_null("Segoe UI", |font_ptr| unsafe {
            CreateFontW(
                -12,
                0,
                0,
                0,
                400, // FW_NORMAL
                0,
                0,
                0,
                1, // DEFAULT_CHARSET
                0,
                0,
                0,
                0,
                font_ptr,
            )
        });

        if !font.is_null() {
            unsafe {
                SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1 as LPARAM);
            }
        }

        // Build status icons image list
        log_to_file("TunnelListView::new(): creating status image list");
        let image_list = Self::create_status_image_list();
        if image_list != 0 {
            unsafe {
                SendMessageW(
                    hwnd,
                    LVM_SETIMAGELIST,
                    LVSIL_SMALL as WPARAM,
                    image_list as LPARAM,
                );
            }
        }
        log_to_file("TunnelListView::new(): done");

        Ok(Self {
            hwnd,
            image_list,
            font,
            tunnels: Vec::new(),
            scratch_wide: Vec::new(),
            is_syncing: false,
        })
    }

    /// Returns the underlying native Win32 `HWND`.
    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }

    /// Resizes and repositions the ListView control.
    pub fn resize(&self, x: i32, y: i32, width: i32, height: i32) {
        unsafe {
            MoveWindow(self.hwnd, x, y, width, height, TRUE);
            // Update column width to match client area
            SendMessageW(self.hwnd, LVM_SETCOLUMNWIDTH, 0, width as LPARAM);
        }
    }

    fn insert_item_at(
        hwnd: HWND,
        index: i32,
        name: &str,
        state: TunnelState,
        lparam: isize,
        scratch: &mut Vec<u16>,
    ) {
        encode_wide_null_into(name, scratch);
        let mut lv_item: LVITEMW = unsafe { std::mem::zeroed() };
        lv_item.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        lv_item.iItem = index;
        lv_item.iSubItem = 0;
        lv_item.pszText = scratch.as_mut_ptr();
        lv_item.iImage = state_to_icon_index(state);
        lv_item.lParam = lparam;
        unsafe {
            SendMessageW(hwnd, LVM_INSERTITEMW, 0, &lv_item as *const _ as LPARAM);
        }
    }

    fn update_item_at(hwnd: HWND, index: i32, state: Option<TunnelState>, lparam: Option<isize>) {
        let mut lv_item: LVITEMW = unsafe { std::mem::zeroed() };
        lv_item.iItem = index;
        lv_item.iSubItem = 0;
        if let Some(s) = state {
            lv_item.mask |= LVIF_IMAGE;
            lv_item.iImage = state_to_icon_index(s);
        }
        if let Some(lp) = lparam {
            lv_item.mask |= LVIF_PARAM;
            lv_item.lParam = lp;
        }
        if lv_item.mask != 0 {
            unsafe {
                SendMessageW(hwnd, LVM_SETITEMW, 0, &lv_item as *const _ as LPARAM);
                if state.is_some() {
                    SendMessageW(hwnd, LVM_REDRAWITEMS, index as WPARAM, index as LPARAM);
                    UpdateWindow(hwnd);
                }
            }
        }
    }

    /// Updates the list of tunnels by diffing against the current rows in place.
    ///
    /// Avoids `LVM_DELETEALLITEMS` + full row recreation when tunnels are added,
    /// removed, or change state, and preserves existing selection automatically.
    pub fn set_tunnels(&mut self, mut new_tunnels: Vec<TunnelItem>) {
        // Natural sort by tunnel name (matching wireguard-windows Go implementation)
        new_tunnels.sort_by(|a, b| cmp_tunnel_name(&a.name, &b.name));

        // Fast path 1: nothing changed at all
        if self.tunnels == new_tunnels {
            if self.selected_index().is_none() && !self.tunnels.is_empty() {
                self.is_syncing = true;
                if !self.select_first_active_tunnel() {
                    self.set_selected_index(0);
                }
                self.is_syncing = false;
            }
            return;
        }

        // Fast path 2: same ordered tunnel names, only states changed
        if self.tunnels.len() == new_tunnels.len()
            && self
                .tunnels
                .iter()
                .zip(new_tunnels.iter())
                .all(|(old, new)| old.name == new.name)
        {
            for (i, new_item) in new_tunnels.iter().enumerate() {
                if self.tunnels[i].state != new_item.state {
                    self.update_tunnel_state_at(i, new_item.state);
                }
            }
            if self.selected_index().is_none() && !self.tunnels.is_empty() {
                self.is_syncing = true;
                if !self.select_first_active_tunnel() {
                    self.set_selected_index(0);
                }
                self.is_syncing = false;
            }
            return;
        }

        // General path: structural add/remove diff in place inside WM_SETREDRAW
        self.is_syncing = true;
        let old_tunnels = std::mem::take(&mut self.tunnels);

        unsafe {
            SendMessageW(self.hwnd, WM_SETREDRAW, FALSE as WPARAM, 0);
        }

        if new_tunnels.is_empty() {
            unsafe {
                SendMessageW(self.hwnd, LVM_DELETEALLITEMS, 0, 0);
            }
        } else {
            let mut oi = 0usize;
            let mut ni = 0usize;
            let mut lv_idx = 0i32;

            while oi < old_tunnels.len() && ni < new_tunnels.len() {
                match cmp_tunnel_name(&old_tunnels[oi].name, &new_tunnels[ni].name) {
                    std::cmp::Ordering::Less => {
                        unsafe {
                            SendMessageW(self.hwnd, LVM_DELETEITEM, lv_idx as WPARAM, 0);
                        }
                        oi += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        Self::insert_item_at(
                            self.hwnd,
                            lv_idx,
                            &new_tunnels[ni].name,
                            new_tunnels[ni].state,
                            ni as isize,
                            &mut self.scratch_wide,
                        );
                        ni += 1;
                        lv_idx += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        let new_state = (old_tunnels[oi].state != new_tunnels[ni].state)
                            .then_some(new_tunnels[ni].state);
                        let new_lparam = (oi != ni).then_some(ni as isize);
                        Self::update_item_at(self.hwnd, lv_idx, new_state, new_lparam);
                        oi += 1;
                        ni += 1;
                        lv_idx += 1;
                    }
                }
            }

            while oi < old_tunnels.len() {
                unsafe {
                    SendMessageW(self.hwnd, LVM_DELETEITEM, lv_idx as WPARAM, 0);
                }
                oi += 1;
            }

            while ni < new_tunnels.len() {
                Self::insert_item_at(
                    self.hwnd,
                    lv_idx,
                    &new_tunnels[ni].name,
                    new_tunnels[ni].state,
                    ni as isize,
                    &mut self.scratch_wide,
                );
                ni += 1;
                lv_idx += 1;
            }
        }

        self.tunnels = new_tunnels;

        unsafe {
            SendMessageW(self.hwnd, WM_SETREDRAW, TRUE as WPARAM, 0);
            InvalidateRect(self.hwnd, ptr::null(), FALSE);
        }

        // Select a default item only if no surviving tunnel retained selection
        if self.selected_index().is_none() && !self.tunnels.is_empty() {
            if !self.select_first_active_tunnel() {
                self.set_selected_index(0);
            }
        }

        self.is_syncing = false;
    }

    /// Updates the state of an existing tunnel at `index` in O(1) time without allocations.
    pub fn update_tunnel_state_at(&mut self, index: usize, state: TunnelState) -> bool {
        if index < self.tunnels.len() {
            if self.tunnels[index].state == state {
                return false;
            }
            self.tunnels[index].state = state;
            Self::update_item_at(self.hwnd, index as i32, Some(state), None);
            true
        } else {
            false
        }
    }

    /// Updates the state of an existing tunnel in place.
    pub fn update_tunnel_state(&mut self, name: &str, state: TunnelState) -> bool {
        if let Some(pos) = self.tunnels.iter().position(|t| t.name == name) {
            self.update_tunnel_state_at(pos, state)
        } else {
            false
        }
    }

    /// Returns a slice reference to the currently selected tunnel's name, avoiding heap allocation.
    pub fn selected_tunnel_str(&self) -> Option<&str> {
        self.selected_index().and_then(|idx| {
            self.tunnels.get(idx).map(|t| t.name.as_str())
        })
    }

    /// Returns the currently selected tunnel's name, or `None` if nothing is selected.
    pub fn selected_tunnel(&self) -> Option<String> {
        self.selected_index().and_then(|idx| {
            if idx < self.tunnels.len() {
                Some(self.tunnels[idx].name.clone())
            } else {
                None
            }
        })
    }

    /// Returns the index of the currently selected item, or `None`.
    pub fn selected_index(&self) -> Option<usize> {
        let idx = unsafe {
            SendMessageW(
                self.hwnd,
                LVM_GETNEXTITEM,
                (-1isize) as WPARAM,
                LVNI_SELECTED as LPARAM,
            )
        };
        if idx >= 0 && (idx as usize) < self.tunnels.len() {
            Some(idx as usize)
        } else {
            None
        }
    }

    /// Selects a tunnel by name. Returns `true` if found and selected.
    pub fn select_tunnel(&self, name: &str) -> bool {
        if let Some(idx) = self.tunnels.iter().position(|t| t.name == name) {
            self.set_selected_index(idx);
            true
        } else {
            false
        }
    }

    /// Selects the item at the specified index.
    pub fn set_selected_index(&self, index: usize) {
        if index >= self.tunnels.len() {
            return;
        }

        // Clear existing selection across all items
        let mut clear_item: LVITEMW = unsafe { std::mem::zeroed() };
        clear_item.state = 0;
        clear_item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;

        unsafe {
            SendMessageW(
                self.hwnd,
                LVM_SETITEMSTATE,
                (-1isize) as WPARAM,
                &clear_item as *const _ as LPARAM,
            );
        }

        // Apply selection and focus to target item
        let mut set_item: LVITEMW = unsafe { std::mem::zeroed() };
        set_item.state = LVIS_SELECTED | LVIS_FOCUSED;
        set_item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;

        unsafe {
            SendMessageW(
                self.hwnd,
                LVM_SETITEMSTATE,
                index as WPARAM,
                &set_item as *const _ as LPARAM,
            );
            SendMessageW(
                self.hwnd,
                LVM_ENSUREVISIBLE,
                index as WPARAM,
                FALSE as LPARAM,
            );
        }
    }

    /// Selects the first active (`Started` or `Starting`) tunnel in the list.
    pub fn select_first_active_tunnel(&self) -> bool {
        for (i, t) in self.tunnels.iter().enumerate() {
            if t.state == TunnelState::Started || t.state == TunnelState::Starting {
                self.set_selected_index(i);
                return true;
            }
        }
        false
    }

    /// Returns a slice over the current tunnel items.
    pub fn tunnels(&self) -> &[TunnelItem] {
        &self.tunnels
    }

    /// Returns the number of tunnel items in the list.
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }

    /// Clears all tunnels from the list view.
    pub fn clear(&mut self) {
        self.tunnels.clear();
        unsafe {
            SendMessageW(self.hwnd, LVM_DELETEALLITEMS, 0, 0);
        }
    }

    /// Handles a Win32 `WM_NOTIFY` message destined for this control.
    ///
    /// Returns `Some(ListViewNotification)` if the notification represents
    /// a selection change or user activation.
    pub fn handle_notify(&mut self, nmhdr: *const NMHDR) -> Option<ListViewNotification> {
        if nmhdr.is_null() {
            return None;
        }

        unsafe {
            if (*nmhdr).hwndFrom != self.hwnd {
                return None;
            }

            let code = (*nmhdr).code;

            if code == LVN_ITEMCHANGED_CODE {
                let nmlv = nmhdr as *const NMLISTVIEW;
                // Check if selection state changed
                if ((*nmlv).uChanged & LVIF_STATE) != 0 {
                    let old_sel = ((*nmlv).uOldState & LVIS_SELECTED) != 0;
                    let new_sel = ((*nmlv).uNewState & LVIS_SELECTED) != 0;
                    if old_sel != new_sel {
                        return Some(ListViewNotification::SelectionChanged(self.selected_tunnel()));
                    }
                }
            } else if code == LVN_ITEMACTIVATE_CODE || code == NM_DBLCLK_CODE || code == NM_RETURN_CODE {
                if let Some(tunnel) = self.selected_tunnel() {
                    return Some(ListViewNotification::ItemActivated(tunnel));
                }
            }
        }

        None
    }

    /// Builds the 16x16 `ImageList` containing colored indicator dots for each state.
    fn create_status_image_list() -> HIMAGELIST {
        unsafe {
            let himl = ImageList_Create(16, 16, ILC_COLOR32, 5, 0);
            if himl == 0 {
                return 0;
            }

            // Index 0: Stopped (Gray)
            let b0 = create_dot_bitmap(COLOR_STATE_STOPPED, 16);
            ImageList_Add(himl, b0, ptr::null_mut());
            DeleteObject(b0 as HGDIOBJ);

            // Index 1: Started (Green)
            let b1 = create_dot_bitmap(COLOR_STATE_STARTED, 16);
            ImageList_Add(himl, b1, ptr::null_mut());
            DeleteObject(b1 as HGDIOBJ);

            // Index 2: Starting (Amber)
            let b2 = create_dot_bitmap(COLOR_STATE_STARTING, 16);
            ImageList_Add(himl, b2, ptr::null_mut());
            DeleteObject(b2 as HGDIOBJ);

            // Index 3: Stopping (Orange)
            let b3 = create_dot_bitmap(COLOR_STATE_STOPPING, 16);
            ImageList_Add(himl, b3, ptr::null_mut());
            DeleteObject(b3 as HGDIOBJ);

            // Index 4: Unknown (Slate)
            let b4 = create_dot_bitmap(COLOR_STATE_UNKNOWN, 16);
            ImageList_Add(himl, b4, ptr::null_mut());
            DeleteObject(b4 as HGDIOBJ);

            himl
        }
    }
}

impl Drop for TunnelListView {
    fn drop(&mut self) {
        unsafe {
            if self.image_list != 0 {
                ImageList_Destroy(self.image_list);
                self.image_list = 0;
            }
            if !self.font.is_null() {
                DeleteObject(self.font as HGDIOBJ);
                self.font = ptr::null_mut();
            }
            if !self.hwnd.is_null() {
                DestroyWindow(self.hwnd);
                self.hwnd = ptr::null_mut();
            }
        }
    }
}

/// Helper function to draw a clean circular status dot into a GDI `HBITMAP`.
unsafe fn create_dot_bitmap(color_bgr: u32, size: i32) -> HBITMAP {
    let screen_dc = GetDC(ptr::null_mut());
    let mem_dc = CreateCompatibleDC(screen_dc);
    let mem_bm = CreateCompatibleBitmap(screen_dc, size, size);
    let old_bm = SelectObject(mem_dc, mem_bm as HGDIOBJ);

    // Background fill matching standard window color
    let bg_brush = GetSysColorBrush(COLOR_WINDOW as i32);
    let rc = RECT {
        left: 0,
        top: 0,
        right: size,
        bottom: size,
    };
    FillRect(mem_dc, &rc, bg_brush);

    // Circle shape with smooth border
    let brush = CreateSolidBrush(color_bgr);
    let pen = CreatePen(PS_SOLID as i32, 1, color_bgr);
    let old_brush = SelectObject(mem_dc, brush as HGDIOBJ);
    let old_pen = SelectObject(mem_dc, pen as HGDIOBJ);

    // Centered 12x12 circle in 16x16 bounds
    let margin = 2;
    Ellipse(mem_dc, margin, margin, size - margin, size - margin);

    // Cleanup GDI objects
    SelectObject(mem_dc, old_pen);
    SelectObject(mem_dc, old_brush);
    DeleteObject(pen as HGDIOBJ);
    DeleteObject(brush as HGDIOBJ);

    SelectObject(mem_dc, old_bm);
    DeleteDC(mem_dc);
    ReleaseDC(ptr::null_mut(), screen_dc);

    mem_bm
}
