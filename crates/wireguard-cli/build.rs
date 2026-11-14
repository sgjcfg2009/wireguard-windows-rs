// SPDX-License-Identifier: MIT
//
// Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
// Build script for wireguard-cli: links precompiled Win32 resources
// (application icon + Common-Controls 6.0 / DPI manifest + version metadata + WireGuardNT driver)
// into wireguard.exe.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../manifest.xml");
    println!("cargo:rerun-if-changed=../../wireguard.ico");
    println!("cargo:rerun-if-changed=../../target/resources.res");

    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&manifest_dir);

    let target_res = workspace_root.join("target").join("resources.res");
    if target_res.exists() {
        println!("cargo:rustc-link-arg={}", target_res.display());
    }
}
