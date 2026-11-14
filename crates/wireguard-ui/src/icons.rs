// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Icon generation, loading, and management for WireGuard Windows UI.
//!
//! Provides RAII management of Win32 `HICON` handles and functions to generate
//! status indicators (active, deactivated, transitioning) and the WireGuard
//! shield logo dynamically via 32-bit GDI DIB sections and `CreateIconIndirect`.
//! Faithfully mirrors `wireguard-windows/ui/iconprovider.go`.

use std::ptr;

use windows_sys::Win32::Graphics::Gdi::{
    CreateBitmap, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject,
    GetDC, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HGDIOBJ,
};
use windows_sys::Win32::UI::Shell::ExtractIconExW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CopyIcon, CreateIconIndirect, DestroyIcon, HICON, ICONINFO,
};

pub use wireguard_types::TunnelState;

/// Safe RAII wrapper around a Win32 `HICON` handle.
///
/// Automatically calls `DestroyIcon` upon drop to prevent GDI resource leaks.
#[derive(Debug)]
pub struct SafeIcon {
    handle: HICON,
}

impl SafeIcon {
    /// Creates a `SafeIcon` from a raw Win32 `HICON` handle.
    pub fn from_raw(handle: HICON) -> Self {
        Self { handle }
    }

    /// Returns the raw Win32 `HICON` handle.
    pub fn handle(&self) -> HICON {
        self.handle
    }

    /// Returns `true` if the underlying handle is non-null.
    pub fn is_valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Consumes the wrapper and returns the raw `HICON`, transferring ownership to the caller.
    pub fn into_raw(mut self) -> HICON {
        let h = self.handle;
        self.handle = ptr::null_mut();
        h
    }

    /// Creates a deep copy of the icon via Win32 `CopyIcon`.
    pub fn try_clone(&self) -> Result<Self, String> {
        if self.handle.is_null() {
            return Ok(Self {
                handle: ptr::null_mut(),
            });
        }
        let copy = unsafe { CopyIcon(self.handle) };
        if copy.is_null() {
            Err("CopyIcon failed to duplicate icon handle".to_string())
        } else {
            Ok(Self { handle: copy })
        }
    }
}

impl Default for SafeIcon {
    fn default() -> Self {
        Self {
            handle: ptr::null_mut(),
        }
    }
}

impl Drop for SafeIcon {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                DestroyIcon(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

unsafe impl Send for SafeIcon {}
unsafe impl Sync for SafeIcon {}

/// Creates a 32-bit ARGB/BGRA anti-aliased `HICON` from a raw pixel buffer.
///
/// `pixels` must contain `width * height * 4` bytes in premultiplied BGRA format.
pub fn create_icon_from_bgra(width: u32, height: u32, pixels: &[u8]) -> Result<SafeIcon, String> {
    let expected_len = (width * height * 4) as usize;
    if pixels.len() != expected_len {
        return Err(format!(
            "Invalid pixel buffer length: expected {}, got {}",
            expected_len,
            pixels.len()
        ));
    }

    unsafe {
        let screen_dc = GetDC(ptr::null_mut());
        if screen_dc.is_null() {
            return Err("GetDC failed to obtain screen DC".to_string());
        }

        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc.is_null() {
            ReleaseDC(ptr::null_mut(), screen_dc);
            return Err("CreateCompatibleDC failed".to_string());
        }

        let bih = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32), // Negative height specifies a top-down DIB
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: (width * height * 4) as u32,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        };

        let bi = BITMAPINFO {
            bmiHeader: bih,
            bmiColors: [std::mem::zeroed(); 1],
        };

        let mut dib_bits: *mut core::ffi::c_void = ptr::null_mut();
        let hbm_color = CreateDIBSection(
            mem_dc,
            &bi,
            DIB_RGB_COLORS,
            &mut dib_bits,
            ptr::null_mut(),
            0,
        );

        if hbm_color.is_null() || dib_bits.is_null() {
            if !hbm_color.is_null() {
                DeleteObject(hbm_color as HGDIOBJ);
            }
            DeleteDC(mem_dc);
            ReleaseDC(ptr::null_mut(), screen_dc);
            return Err("CreateDIBSection failed to create 32bpp DIB".to_string());
        }

        // Copy premultiplied BGRA pixels into the allocated DIB section
        ptr::copy_nonoverlapping(pixels.as_ptr(), dib_bits as *mut u8, pixels.len());

        // Create monochrome 1-bpp mask bitmap (all 0s = transparency dictated by 32-bit alpha channel)
        let mask_stride = ((width + 31) / 32) * 4;
        let mask_bytes = vec![0u8; (mask_stride * height) as usize];
        let hbm_mask = CreateBitmap(
            width as i32,
            height as i32,
            1,
            1,
            mask_bytes.as_ptr() as *const core::ffi::c_void,
        );

        if hbm_mask.is_null() {
            DeleteObject(hbm_color as HGDIOBJ);
            DeleteDC(mem_dc);
            ReleaseDC(ptr::null_mut(), screen_dc);
            return Err("CreateBitmap for 1bpp mask failed".to_string());
        }

        let icon_info = ICONINFO {
            fIcon: 1, // TRUE: creates an Icon, not a Cursor
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: hbm_mask,
            hbmColor: hbm_color,
        };

        let hicon = CreateIconIndirect(&icon_info);

        // Win32 CreateIconIndirect creates internal copies of the bitmaps; release originals
        DeleteObject(hbm_mask as HGDIOBJ);
        DeleteObject(hbm_color as HGDIOBJ);
        DeleteDC(mem_dc);
        ReleaseDC(ptr::null_mut(), screen_dc);

        if hicon.is_null() {
            Err("CreateIconIndirect failed to generate HICON".to_string())
        } else {
            Ok(SafeIcon::from_raw(hicon))
        }
    }
}

/// Renders a smoothed, anti-aliased circular status dot with 3D gradient highlight and border.
///
/// Returns premultiplied BGRA bytes for a `size x size` bitmap.
fn draw_status_dot(size: u32, fill_rgb: [u8; 3], border_rgb: [u8; 3]) -> Vec<u8> {
    let mut pixels = vec![0u8; (size * size * 4) as usize];
    let cx = (size as f32) / 2.0;
    let cy = (size as f32) / 2.0;
    let r_outer = (size as f32) * 0.42;
    let border_width = ((size as f32) * 0.10).max(1.0);
    let r_inner = r_outer - border_width;

    for y in 0..size {
        for x in 0..size {
            let px = (x as f32) + 0.5;
            let py = (y as f32) + 0.5;
            let dx = px - cx;
            let dy = py - cy;
            let dist = (dx * dx + dy * dy).sqrt();

            // Antialiased outer boundary coverage
            let outer_cov = if dist <= r_outer - 0.5 {
                1.0
            } else if dist >= r_outer + 0.5 {
                0.0
            } else {
                r_outer + 0.5 - dist
            };

            if outer_cov <= 0.0 {
                continue;
            }

            // Antialiased inner boundary coverage (fill vs border)
            let inner_cov = if dist <= r_inner - 0.5 {
                1.0
            } else if dist >= r_inner + 0.5 {
                0.0
            } else {
                r_inner + 0.5 - dist
            };

            let border_cov = 1.0 - inner_cov;

            // Subtle top-left to bottom-right specular lighting for 3D depth
            let light = 1.0 - 0.20 * (dx + dy) / r_outer;
            let light = light.clamp(0.80, 1.20);

            let r = (fill_rgb[0] as f32 * inner_cov * light + border_rgb[0] as f32 * border_cov)
                .clamp(0.0, 255.0);
            let g = (fill_rgb[1] as f32 * inner_cov * light + border_rgb[1] as f32 * border_cov)
                .clamp(0.0, 255.0);
            let b = (fill_rgb[2] as f32 * inner_cov * light + border_rgb[2] as f32 * border_cov)
                .clamp(0.0, 255.0);

            let alpha = outer_cov.clamp(0.0, 1.0);

            // Store in premultiplied BGRA format
            let b_pre = (b * alpha).round() as u8;
            let g_pre = (g * alpha).round() as u8;
            let r_pre = (r * alpha).round() as u8;
            let a_byte = (alpha * 255.0).round() as u8;

            let idx = ((y * size + x) * 4) as usize;
            pixels[idx] = b_pre;
            pixels[idx + 1] = g_pre;
            pixels[idx + 2] = r_pre;
            pixels[idx + 3] = a_byte;
        }
    }

    pixels
}

/// Renders the WireGuard shield logo into a premultiplied BGRA buffer.
///
/// Features the signature deep crimson red shield (`#871719`) with an anti-aliased
/// contour border and stylized dragon knot emblem in the center.
fn draw_logo_shield(size: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (size * size * 4) as usize];
    let cx = (size as f32) / 2.0;
    let y_top = (size as f32) * 0.08;
    let y_bottom = (size as f32) * 0.92;
    let h = y_bottom - y_top;
    let w_max = (size as f32) * 0.40;
    let border_th = ((size as f32) * 0.08).max(1.0);

    // WireGuard brand colors
    let crimson_fill = [135.0f32, 23.0f32, 25.0f32]; // #871719
    let dark_border = [90.0f32, 14.0f32, 16.0f32];   // #5A0E10

    for y in 0..size {
        for x in 0..size {
            let px = (x as f32) + 0.5;
            let py = (y as f32) + 0.5;

            if py < y_top - 0.5 || py > y_bottom + 0.5 {
                continue;
            }

            let t = ((py - y_top) / h).clamp(0.0, 1.0);

            // Top contour with a subtle curve dipping slightly at edges
            let top_arch = y_top + 0.04 * (size as f32) * ((px - cx) / w_max).powi(2);

            // Shield width profile
            let half_w = if t <= 0.38 {
                w_max * (1.0 - 0.06 * t)
            } else {
                let s = (t - 0.38) / 0.62;
                w_max * (1.0 - 0.06 * 0.38) * (1.0 - s.powf(1.5)).max(0.0)
            };

            let dx = half_w - (px - cx).abs();

            let cov_top = (py - top_arch + 0.5).clamp(0.0, 1.0);
            let cov_bottom = (y_bottom + 0.5 - py).clamp(0.0, 1.0);
            let cov_side = (dx + 0.5).clamp(0.0, 1.0);
            let shield_alpha = cov_top.min(cov_bottom).min(cov_side);

            if shield_alpha <= 0.0 {
                continue;
            }

            // Determine if on border or in shield interior
            let is_border = dx < border_th
                || py < top_arch + border_th
                || py > y_bottom - border_th * 1.5;

            let (base_r, base_g, base_b) = if is_border {
                (dark_border[0], dark_border[1], dark_border[2])
            } else {
                let light = 1.0 - 0.15 * ((px - cx) + (py - (y_top + h * 0.45))) / w_max;
                let light = light.clamp(0.85, 1.15);
                (
                    (crimson_fill[0] * light).clamp(0.0, 255.0),
                    (crimson_fill[1] * light).clamp(0.0, 255.0),
                    (crimson_fill[2] * light).clamp(0.0, 255.0),
                )
            };

            // Stylized white emblem in the center of the shield
            let mut final_r = base_r;
            let mut final_g = base_g;
            let mut final_b = base_b;

            if !is_border {
                let emblem_cy = y_top + h * 0.45;
                let edx = px - cx;
                let edy = py - emblem_cy;
                let dist_e = (edx * edx + edy * edy).sqrt();
                let angle_e = edy.atan2(edx);

                // Spiral knot curve for WireGuard dragon emblem
                let emblem_r = w_max * 0.48;
                let spiral_dist = (angle_e + std::f32::consts::PI) / (2.0 * std::f32::consts::PI);
                let target_r = emblem_r * (0.35 + 0.50 * spiral_dist);
                let dr = (dist_e - target_r).abs();
                let band_th = ((size as f32) * 0.08).max(1.0);

                if dr < band_th && dist_e <= emblem_r && dist_e >= emblem_r * 0.20 {
                    let white_cov = (1.0 - dr / band_th).clamp(0.0, 1.0);
                    final_r = final_r * (1.0 - white_cov) + 255.0 * white_cov;
                    final_g = final_g * (1.0 - white_cov) + 255.0 * white_cov;
                    final_b = final_b * (1.0 - white_cov) + 255.0 * white_cov;
                }
            }

            // Premultiplied BGRA output
            let b_pre = (final_b * shield_alpha).round() as u8;
            let g_pre = (final_g * shield_alpha).round() as u8;
            let r_pre = (final_r * shield_alpha).round() as u8;
            let a_byte = (shield_alpha * 255.0).round() as u8;

            let idx = ((y * size + x) * 4) as usize;
            pixels[idx] = b_pre;
            pixels[idx + 1] = g_pre;
            pixels[idx + 2] = r_pre;
            pixels[idx + 3] = a_byte;
        }
    }

    pixels
}

/// Creates a status indicator icon for the **Active** (connected) state.
///
/// Generates a vibrant green anti-aliased dot.
pub fn create_active_icon(size: u32) -> Result<SafeIcon, String> {
    // RGB(46, 125, 50) fill with RGB(27, 94, 32) border
    let pixels = draw_status_dot(size, [46, 125, 50], [27, 94, 32]);
    create_icon_from_bgra(size, size, &pixels)
}

/// Creates a status indicator icon for the **Deactivated** (disconnected) state.
///
/// Generates a neutral gray anti-aliased dot.
pub fn create_deactivated_icon(size: u32) -> Result<SafeIcon, String> {
    // RGB(158, 158, 158) fill with RGB(97, 97, 97) border
    let pixels = draw_status_dot(size, [158, 158, 158], [97, 97, 97]);
    create_icon_from_bgra(size, size, &pixels)
}

/// Creates a status indicator icon for the **Transitioning** (activating/deactivating) state.
///
/// Generates a vibrant amber/yellow anti-aliased dot.
pub fn create_transitioning_icon(size: u32) -> Result<SafeIcon, String> {
    // RGB(255, 179, 0) fill with RGB(230, 81, 0) border
    let pixels = draw_status_dot(size, [255, 179, 0], [230, 81, 0]);
    create_icon_from_bgra(size, size, &pixels)
}

/// Creates the official WireGuard shield logo icon.
///
/// Generates a crimson red shield (`#871719`) with a white dragon crest.
pub fn create_logo_icon(size: u32) -> Result<SafeIcon, String> {
    let pixels = draw_logo_shield(size);
    create_icon_from_bgra(size, size, &pixels)
}

/// Creates an icon consisting of the WireGuard logo with a state badge overlaid in the bottom-right corner.
///
/// Matches Go implementation `iconWithOverlayForState` in `wireguard-windows/ui/iconprovider.go`.
pub fn create_overlay_icon(state: TunnelState, size: u32) -> Result<SafeIcon, String> {
    let mut pixels = draw_logo_shield(size);

    // If completely stopped, WireGuard displays the clean plain logo without overlay
    if state == TunnelState::Stopped {
        return create_icon_from_bgra(size, size, &pixels);
    }

    // Overlay dot geometry in bottom-right corner
    let dot_cx = (size as f32) * 0.76;
    let dot_cy = (size as f32) * 0.76;
    let dot_r_outer = (size as f32) * 0.24;
    let dot_border_th = ((size as f32) * 0.05).max(1.0);
    let dot_r_inner = dot_r_outer - dot_border_th;

    let (fill_rgb, border_rgb) = match state {
        TunnelState::Started => ([46u8, 125, 50], [27u8, 94, 32]), // Green
        TunnelState::Starting | TunnelState::Stopping => ([255u8, 179, 0], [230u8, 81, 0]), // Amber
        _ => ([158u8, 158, 158], [97u8, 97, 97]),                  // Gray
    };

    // Dark separation ring around badge to separate it from red shield background
    let dark_ring_r = dot_r_outer + ((size as f32) * 0.04).max(1.0);

    for y in 0..size {
        for x in 0..size {
            let px = (x as f32) + 0.5;
            let py = (y as f32) + 0.5;
            let dx = px - dot_cx;
            let dy = py - dot_cy;
            let dist = (dx * dx + dy * dy).sqrt();

            if dist > dark_ring_r + 0.5 {
                continue;
            }

            let idx = ((y * size + x) * 4) as usize;

            // Check if inside separation ring
            if dist > dot_r_outer + 0.5 {
                let ring_cov = (dark_ring_r + 0.5 - dist).clamp(0.0, 0.8);
                // Blend with dark background outline
                let inv = 1.0 - ring_cov;
                pixels[idx] = (pixels[idx] as f32 * inv) as u8;
                pixels[idx + 1] = (pixels[idx + 1] as f32 * inv) as u8;
                pixels[idx + 2] = (pixels[idx + 2] as f32 * inv) as u8;
                continue;
            }

            // Dot coverage
            let dot_cov = if dist <= dot_r_outer - 0.5 {
                1.0
            } else {
                (dot_r_outer + 0.5 - dist).clamp(0.0, 1.0)
            };

            let inner_cov = if dist <= dot_r_inner - 0.5 {
                1.0
            } else if dist >= dot_r_inner + 0.5 {
                0.0
            } else {
                (dot_r_inner + 0.5 - dist).clamp(0.0, 1.0)
            };

            let border_cov = 1.0 - inner_cov;
            let light = (1.0 - 0.20 * (dx + dy) / dot_r_outer).clamp(0.80, 1.20);

            let r = (fill_rgb[0] as f32 * inner_cov * light + border_rgb[0] as f32 * border_cov)
                .clamp(0.0, 255.0);
            let g = (fill_rgb[1] as f32 * inner_cov * light + border_rgb[1] as f32 * border_cov)
                .clamp(0.0, 255.0);
            let b = (fill_rgb[2] as f32 * inner_cov * light + border_rgb[2] as f32 * border_cov)
                .clamp(0.0, 255.0);

            // Composite over base pixel
            let dot_alpha = dot_cov.clamp(0.0, 1.0);
            let inv_alpha = 1.0 - dot_alpha;

            let cur_b = pixels[idx] as f32;
            let cur_g = pixels[idx + 1] as f32;
            let cur_r = pixels[idx + 2] as f32;
            let cur_a = pixels[idx + 3] as f32;

            let out_b = (b * dot_alpha + cur_b * inv_alpha).min(255.0);
            let out_g = (g * dot_alpha + cur_g * inv_alpha).min(255.0);
            let out_r = (r * dot_alpha + cur_r * inv_alpha).min(255.0);
            let out_a = (dot_alpha * 255.0 + cur_a * inv_alpha).min(255.0);

            pixels[idx] = out_b.round() as u8;
            pixels[idx + 1] = out_g.round() as u8;
            pixels[idx + 2] = out_r.round() as u8;
            pixels[idx + 3] = out_a.round() as u8;
        }
    }

    create_icon_from_bgra(size, size, &pixels)
}

/// Returns a status indicator dot for the specified `TunnelState`.
pub fn icon_for_state(state: TunnelState, size: u32) -> Result<SafeIcon, String> {
    match state {
        TunnelState::Started => create_active_icon(size),
        TunnelState::Stopped => create_deactivated_icon(size),
        TunnelState::Starting | TunnelState::Stopping => create_transitioning_icon(size),
        TunnelState::Unknown => create_deactivated_icon(size),
    }
}

/// Returns the WireGuard logo with an overlay badge for the specified `TunnelState`.
pub fn icon_with_overlay_for_state(state: TunnelState, size: u32) -> Result<SafeIcon, String> {
    create_overlay_icon(state, size)
}

/// Attempts to load an icon from a Windows system DLL (e.g. `imageres.dll`, `shell32.dll`).
///
/// Falls back to our programmatic icon generator if extraction fails.
pub fn load_system_icon(dll: &str, index: i32, size: u32) -> Result<SafeIcon, String> {
    let mut hicon_large: HICON = ptr::null_mut();
    let mut hicon_small: HICON = ptr::null_mut();

    let count = crate::win32_util::with_wide_null(dll, |dll_w| unsafe {
        ExtractIconExW(
            dll_w,
            index,
            &mut hicon_large,
            &mut hicon_small,
            1,
        )
    });

    if count == 0 {
        return Err(format!("ExtractIconExW failed for {dll} at index {index}"));
    }

    // For tray sizes (<= 32px), prefer small icon; otherwise prefer large
    let (chosen, discarded) = if size <= 32 && !hicon_small.is_null() {
        (hicon_small, hicon_large)
    } else if !hicon_large.is_null() {
        (hicon_large, hicon_small)
    } else {
        (hicon_small, ptr::null_mut())
    };

    if !discarded.is_null() {
        unsafe {
            DestroyIcon(discarded);
        }
    }

    if chosen.is_null() {
        Err("No icon extracted from system DLL".to_string())
    } else {
        Ok(SafeIcon::from_raw(chosen))
    }
}
