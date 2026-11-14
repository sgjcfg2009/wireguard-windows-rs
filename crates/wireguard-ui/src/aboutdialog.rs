// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Native Win32 "About WireGuard" modal dialog for WireGuard Windows (100% Rust).
//!
//! Faithful port of `wireguard-windows/ui/aboutdialog.go`.
//! Displays the WireGuard logo emblem, version information, operating system,
//! architecture, copyright statement, and interactive links to wireguard.com.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Once;

use windows_sys::Win32::Foundation::{
    FALSE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, TRUE, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreatePen, CreateSolidBrush, DeleteObject, EndPaint,
    GetSysColorBrush, Polygon, RoundRect, SelectObject, SetBkMode, SetTextColor,
    COLOR_BTNFACE, FW_BOLD, FW_NORMAL, HBRUSH, HDC, HFONT, PAINTSTRUCT, PS_SOLID,
    TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, VK_ESCAPE, VK_RETURN};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetClientRect, GetMessageW, GetSystemMetrics, GetWindowRect, IsWindow, LoadCursorW,
    RegisterClassExW, SendMessageW, SetForegroundWindow, SetWindowLongPtrW,
    ShowWindow, TranslateMessage, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CS_HREDRAW,
    CS_VREDRAW, GWLP_USERDATA, IDC_ARROW, SM_CXSCREEN, SM_CYSCREEN,
    SW_SHOW, SW_SHOWNORMAL,
    WM_CLOSE, WM_COMMAND, WM_CTLCOLORSTATIC, WM_DESTROY, WM_KEYDOWN,
    WM_PAINT, WM_SETFONT, WNDCLASSEXW, WS_CAPTION, WS_CHILD, WS_EX_DLGMODALFRAME, WS_POPUP,
    WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

use crate::win32_util::with_wide_null;

/// SS_CENTER static control style.
const SS_CENTER: u32 = 0x00000001;

/// Window class name for the About Dialog.
const ABOUT_DIALOG_CLASS: &str = "WireGuardAboutDialog";

/// Atomic handle of the currently displayed About Dialog to prevent duplicates.
static SHOWING_ABOUT_DIALOG: AtomicIsize = AtomicIsize::new(0);

/// Control identifiers for child elements in the dialog.
const ID_BTN_WEBSITE: usize = 3001;
const ID_BTN_DONATE: usize = 3002;
const ID_BTN_CLOSE: usize = 3003;

/// Internal state holding GDI font handles for cleanup.
struct AboutDialogState {
    font_title: HFONT,
    font_body: HFONT,
    font_copyright: HFONT,
    _parent_hwnd: HWND,
}

/// Registers the Win32 window class for the about dialog once.
fn register_about_class(h_instance: HINSTANCE) {
    static REGISTER_ONCE: Once = Once::new();
    REGISTER_ONCE.call_once(|| {
        with_wide_null(ABOUT_DIALOG_CLASS, |class_ptr| {
            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(about_wnd_proc),
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

/// Main entry point to display the "About WireGuard" modal dialog.
///
/// Matches `runAboutDialog(owner walk.Form)` in `aboutdialog.go`.
pub fn run_about_dialog(parent: HWND) {
    // If dialog is already showing, bring it to the front
    let existing = SHOWING_ABOUT_DIALOG.load(Ordering::SeqCst);
    if existing != 0 as isize && unsafe { IsWindow(existing as HWND) } != 0 {
        unsafe {
            ShowWindow(existing as HWND, SW_SHOW);
            SetForegroundWindow(existing as HWND);
        }
        return;
    }

    let h_instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    register_about_class(h_instance);

    let dlg_width = 440;
    let dlg_height = 380;

    // Center dialog over parent window or desktop
    let (mut x, mut y) = (100, 100);
    if parent != std::ptr::null_mut() {
        let mut parent_rect: RECT = unsafe { std::mem::zeroed() };
        if unsafe { GetWindowRect(parent, &mut parent_rect) } != 0 {
            let pw = parent_rect.right - parent_rect.left;
            let ph = parent_rect.bottom - parent_rect.top;
            x = parent_rect.left + (pw - dlg_width) / 2;
            y = parent_rect.top + (ph - dlg_height) / 2;
        }
    } else {
        let screen_w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let screen_h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        x = (screen_w - dlg_width) / 2;
        y = (screen_h - dlg_height) / 2;
    }

    let hwnd = with_wide_null("About WireGuard", |title_ptr| {
        with_wide_null(ABOUT_DIALOG_CLASS, |class_ptr| unsafe {
            CreateWindowExW(
                WS_EX_DLGMODALFRAME,
                class_ptr,
                title_ptr,
                WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                x,
                y,
                dlg_width,
                dlg_height,
                parent,
                std::ptr::null_mut(),
                h_instance,
                std::ptr::null(),
            )
        })
    });

    if hwnd == std::ptr::null_mut() {
        return;
    }

    SHOWING_ABOUT_DIALOG.store(hwnd as isize, Ordering::SeqCst);

    // Create GUI fonts: Segoe UI
    let (font_title, font_body, font_copyright) = with_wide_null("Segoe UI", |font_ptr| unsafe {
        let title = CreateFontW(
            28, // height
            0,
            0,
            0,
            FW_BOLD as i32,
            0,
            0,
            0,
            1, // DEFAULT_CHARSET
            0,
            0,
            0,
            0,
            font_ptr,
        );
        let body = CreateFontW(
            15, // height (~9pt)
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
        );
        let copyright = CreateFontW(
            13, // height (~7.5pt)
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
        );
        (title, body, copyright)
    });

    let state = Box::new(AboutDialogState {
        font_title,
        font_body,
        font_copyright,
        _parent_hwnd: parent,
    });

    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
    }

    // Initialize child controls inside the about dialog
    setup_dialog_controls(hwnd, font_title, font_body, font_copyright, h_instance);

    // Disable parent window to enforce modal behavior
    if parent != std::ptr::null_mut() {
        unsafe {
            EnableWindow(parent, FALSE);
        }
    }

    // Modal message loop
    unsafe {
        let mut msg = std::mem::zeroed();
        while IsWindow(hwnd) != 0 && GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if msg.message == WM_KEYDOWN
                && (msg.wParam == VK_ESCAPE as usize || msg.wParam == VK_RETURN as usize)
            {
                DestroyWindow(hwnd);
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Re-enable parent window upon dialog exit
        if parent != std::ptr::null_mut() {
            EnableWindow(parent, TRUE);
            SetForegroundWindow(parent);
        }
    }

    SHOWING_ABOUT_DIALOG.store(0, Ordering::SeqCst);
}

/// Instantiates child labels, version information, and buttons inside the dialog.
fn setup_dialog_controls(
    hwnd: HWND,
    font_title: HFONT,
    font_body: HFONT,
    font_copyright: HFONT,
    h_instance: HINSTANCE,
) {
    // Version details text
    let version_info = format!(
        "WireGuard for Windows v{} (100% Rust)\n\
         Driver: WireGuardNT (Rust native)\n\
         Operating system: {}\n\
         Architecture: {}",
        env!("CARGO_PKG_VERSION"),
        wireguard_version::os_name(),
        wireguard_version::arch()
    );

    with_wide_null("STATIC", |static_ptr| {
        // Title label: "WireGuard"
        let hwnd_title = with_wide_null("WireGuard", |title_ptr| unsafe {
            CreateWindowExW(
                0,
                static_ptr,
                title_ptr,
                WS_CHILD | WS_VISIBLE | SS_CENTER,
                20,
                85,
                390,
                32,
                hwnd,
                std::ptr::null_mut(),
                h_instance,
                std::ptr::null(),
            )
        });
        if !hwnd_title.is_null() && !font_title.is_null() {
            unsafe {
                SendMessageW(hwnd_title, WM_SETFONT, font_title as WPARAM, 1);
            }
        }

        let hwnd_details = with_wide_null(&version_info, |details_ptr| unsafe {
            CreateWindowExW(
                0,
                static_ptr,
                details_ptr,
                WS_CHILD | WS_VISIBLE | SS_CENTER,
                20,
                125,
                390,
                80,
                hwnd,
                std::ptr::null_mut(),
                h_instance,
                std::ptr::null(),
            )
        });
        if !hwnd_details.is_null() && !font_body.is_null() {
            unsafe {
                SendMessageW(hwnd_details, WM_SETFONT, font_body as WPARAM, 1);
            }
        }

        // Copyright notice text
        let hwnd_copyright = with_wide_null(
            "Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.",
            |copyright_ptr| unsafe {
                CreateWindowExW(
                    0,
                    static_ptr,
                    copyright_ptr,
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    20,
                    218,
                    390,
                    20,
                    hwnd,
                    std::ptr::null_mut(),
                    h_instance,
                    std::ptr::null(),
                )
            },
        );
        if !hwnd_copyright.is_null() && !font_copyright.is_null() {
            unsafe {
                SendMessageW(hwnd_copyright, WM_SETFONT, font_copyright as WPARAM, 1);
            }
        }
    });

    with_wide_null("BUTTON", |button_ptr| {
        // Website Button: "https://www.wireguard.com/"
        let hwnd_web = with_wide_null("https://www.wireguard.com/", |website_ptr| unsafe {
            CreateWindowExW(
                0,
                button_ptr,
                website_ptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                110,
                250,
                210,
                26,
                hwnd,
                ID_BTN_WEBSITE as _,
                h_instance,
                std::ptr::null(),
            )
        });
        if !hwnd_web.is_null() && !font_body.is_null() {
            unsafe {
                SendMessageW(hwnd_web, WM_SETFONT, font_body as WPARAM, 1);
            }
        }

        // Action buttons bar at bottom: "♥ Donate!" and "Close"
        let hwnd_donate = with_wide_null("♥ Donate!", |donate_ptr| unsafe {
            CreateWindowExW(
                0,
                button_ptr,
                donate_ptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                105,
                295,
                105,
                28,
                hwnd,
                ID_BTN_DONATE as _,
                h_instance,
                std::ptr::null(),
            )
        });
        if !hwnd_donate.is_null() && !font_body.is_null() {
            unsafe {
                SendMessageW(hwnd_donate, WM_SETFONT, font_body as WPARAM, 1);
            }
        }

        let hwnd_close = with_wide_null("Close", |close_ptr| unsafe {
            CreateWindowExW(
                0,
                button_ptr,
                close_ptr,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
                225,
                295,
                105,
                28,
                hwnd,
                ID_BTN_CLOSE as _,
                h_instance,
                std::ptr::null(),
            )
        });
        if !hwnd_close.is_null() && !font_body.is_null() {
            unsafe {
                SendMessageW(hwnd_close, WM_SETFONT, font_body as WPARAM, 1);
            }
        }
    });
}

/// Paints the custom WireGuard stylized logo emblem at the top of the dialog.
fn paint_wireguard_logo(hdc: HDC, center_x: i32, top_y: i32) {
    // WireGuard brand color: deep crimson / dark red #88171A (BGR: 0x001A1788)
    const WG_RED: u32 = 0x001A1788;
    const WG_BORDER: u32 = 0x00101060;

    unsafe {
        let brush = CreateSolidBrush(WG_RED);
        let pen = CreatePen(PS_SOLID as i32, 2, WG_BORDER);
        let old_brush = SelectObject(hdc, brush);
        let old_pen = SelectObject(hdc, pen);

        // Draw outer shield / emblem
        let radius = 28;
        let left = center_x - radius;
        let right = center_x + radius;
        let top = top_y;
        let bottom = top_y + (radius * 2);

        RoundRect(hdc, left, top, right, bottom, 16, 16);

        // Draw inner decorative stylized knot points
        let pts = [
            POINT {
                x: center_x,
                y: top + 10,
            },
            POINT {
                x: right - 12,
                y: top + 26,
            },
            POINT {
                x: center_x + 8,
                y: bottom - 12,
            },
            POINT {
                x: center_x,
                y: bottom - 18,
            },
            POINT {
                x: center_x - 8,
                y: bottom - 12,
            },
            POINT {
                x: left + 12,
                y: top + 26,
            },
        ];

        let white_brush = CreateSolidBrush(0x00FFFFFF);
        let white_pen = CreatePen(PS_SOLID as i32, 1, 0x00EEEEEE);
        SelectObject(hdc, white_brush);
        SelectObject(hdc, white_pen);

        Polygon(hdc, pts.as_ptr(), pts.len() as i32);

        // Restore DC objects
        SelectObject(hdc, old_pen);
        SelectObject(hdc, old_brush);
        DeleteObject(white_pen);
        DeleteObject(white_brush);
        DeleteObject(pen);
        DeleteObject(brush);
    }
}

/// Win32 Window Procedure for the About Dialog.
unsafe extern "system" fn about_wnd_proc(
    hwnd: HWND,
    msg: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);
            if hdc != std::ptr::null_mut() {
                let mut rect: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rect);
                let center_x = (rect.right - rect.left) / 2;
                paint_wireguard_logo(hdc, center_x, 15);
                EndPaint(hwnd, &ps);
            }
            0
        }

        WM_CTLCOLORSTATIC => {
            let hdc = w_param as HDC;
            SetBkMode(hdc, TRANSPARENT as i32);
            SetTextColor(hdc, 0x00202020);
            GetSysColorBrush(COLOR_BTNFACE) as LRESULT
        }

        WM_COMMAND => {
            let ctrl_id = (w_param & 0xFFFF) as usize;
            match ctrl_id {
                ID_BTN_WEBSITE => {
                    with_wide_null("open", |op_ptr| {
                        with_wide_null("https://www.wireguard.com/", |url_ptr| unsafe {
                            ShellExecuteW(
                                hwnd,
                                op_ptr,
                                url_ptr,
                                std::ptr::null(),
                                std::ptr::null(),
                                SW_SHOWNORMAL,
                            );
                        });
                    });
                }
                ID_BTN_DONATE => {
                    with_wide_null("open", |op_ptr| {
                        with_wide_null("https://www.wireguard.com/donations/", |url_ptr| unsafe {
                            ShellExecuteW(
                                hwnd,
                                op_ptr,
                                url_ptr,
                                std::ptr::null(),
                                std::ptr::null(),
                                SW_SHOWNORMAL,
                            );
                        });
                    });
                    DestroyWindow(hwnd);
                }
                ID_BTN_CLOSE => {
                    DestroyWindow(hwnd);
                }
                _ => {}
            }
            0
        }

        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }

        WM_DESTROY => {
            let state_ptr =
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut AboutDialogState;
            if !state_ptr.is_null() {
                let state = Box::from_raw(state_ptr);
                if state.font_title != std::ptr::null_mut() {
                    DeleteObject(state.font_title);
                }
                if state.font_body != std::ptr::null_mut() {
                    DeleteObject(state.font_body);
                }
                if state.font_copyright != std::ptr::null_mut() {
                    DeleteObject(state.font_copyright);
                }
            }
            SHOWING_ABOUT_DIALOG.store(0, Ordering::SeqCst);
            0
        }

        _ => DefWindowProcW(hwnd, msg, w_param, l_param),
    }
}
