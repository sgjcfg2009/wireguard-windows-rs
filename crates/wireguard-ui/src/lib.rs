// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Rust implementation: 2026 WireGuard Rust Contributors.

//! Native Win32 UI implementation for WireGuard Windows in 100% Rust.
//! Ported faithfully from `wireguard-windows-master/ui`.

pub mod window;
pub mod raise;
pub mod tray;
pub mod icons;
pub mod tunnelspage;
pub mod listview;
pub mod editdialog;
pub mod logpage;
pub mod aboutdialog;
pub mod filesave;
pub(crate) mod win32_util;

pub use aboutdialog::run_about_dialog;
pub use editdialog::run_edit_dialog;
pub use icons::SafeIcon;
pub use listview::TunnelListView;
pub use logpage::LogPage;
pub use raise::{ensure_single_instance, raise, raise_ui};
pub use tray::Tray;
pub use tunnelspage::TunnelsPage;
pub use window::{log_to_file, run_ui, run_ui_tray, ManageTunnelsWindow};
