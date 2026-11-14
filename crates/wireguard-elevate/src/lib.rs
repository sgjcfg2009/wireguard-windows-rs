/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Rust implementation: 2026 WireGuard Rust Contributors.
 */

//! Windows privilege elevation, token manipulation, UAC handling, and impersonation.
//!
//! This crate is a 100% Rust re-implementation of WireGuard Windows's `elevate` package.
//! It provides:
//! - Privilege management: [`drop_all_privileges`], [`enable_privilege`], [`remove_privileges_except`].
//! - Token elevation & UAC queries: [`is_token_elevated`], [`get_linked_token`], [`token_is_elevated_or_elevatable`].
//! - Group membership checks: [`is_token_admin`], [`is_token_network_configuration_operator`].
//! - Impersonation routines: [`do_as_system`], [`do_as_service`], [`ImpersonationGuard`].
//! - Process launching: [`create_process_with_token`], [`create_process_as_user`], [`SpawnedProcess`].
//! - UAC process elevation: [`shell_execute`], [`shell_execute_runas`].
//! - Safe RAII token abstraction: [`Token`], [`AutoHandle`].

pub mod doas;
pub mod error;
pub mod handle;
pub mod membership;
pub mod privilege;
pub mod shellexecute;
pub mod spawn;
pub mod token;

// Re-export core error types
pub use error::{ElevateError, Result};

// Re-export RAII handles and guards
pub use handle::{AutoHandle, AutoServiceHandle, ImpersonationGuard};

// Re-export privilege management functions
pub use privilege::{
    drop_all_privileges, enable_current_process_privilege, enable_current_thread_privilege,
    enable_privilege, remove_privileges_except, remove_process_privileges_except,
};

// Re-export membership and UAC elevation functions
pub use membership::{
    admin_group_name, get_linked_token, is_admin_desktop, is_current_process_elevated,
    is_token_admin, is_token_admin_or_netops, is_token_elevated,
    is_token_member_of_well_known_sid, is_token_network_configuration_operator,
    network_configuration_operators_group_name, token_is_elevated_or_elevatable,
};

// Re-export process spawning functions and constants
pub use spawn::{
    create_process_as_user, create_process_with_token, spawn_as_user, spawn_command_as_user,
    spawn_command_with_token, spawn_with_token, SpawnedProcess, CREATE_NEW_CONSOLE,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, LOGON_NETCREDENTIALS_ONLY, LOGON_WITH_PROFILE,
};

// Re-export DoAs impersonation functions
pub use doas::{do_as_service, do_as_system};

// Re-export ShellExecute functions and display constants
pub use shellexecute::{
    shell_execute, shell_execute_runas, SHOW_DEFAULT, SHOW_HIDDEN, SHOW_NORMAL,
};

// Re-export the high-level Token type
pub use token::Token;

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::TOKEN_QUERY;

    #[test]
    fn test_auto_handle_null_and_invalid() {
        assert!(AutoHandle::new(core::ptr::null_mut()).is_none());
        assert!(AutoHandle::new(-1isize as HANDLE).is_none());
    }

    #[test]
    fn test_admin_group_names() {
        let admin_name = admin_group_name();
        assert!(!admin_name.is_empty(), "Admin group name should not be empty");

        let netops_name = network_configuration_operators_group_name();
        assert!(
            !netops_name.is_empty(),
            "NetOps group name should not be empty"
        );
    }

    #[test]
    fn test_current_process_token_query() {
        let token = Token::open_current_process(TOKEN_QUERY);
        assert!(token.is_ok(), "Should be able to open current process token");
        let token = token.unwrap();

        // Querying elevation should return without errors
        let elevated = token.is_elevated();
        assert!(elevated.is_ok(), "Should query elevation state");

        // Membership checks should execute cleanly
        let _ = token.is_admin();
        let _ = token.is_network_configuration_operator();
        let _ = token.is_elevated_or_elevatable();
    }

    #[test]
    fn test_impersonation_guard_dismiss() {
        let guard = ImpersonationGuard::new();
        guard.dismiss();
    }
}
