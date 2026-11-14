/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Ported to Rust for wireguard-windows-rs.
 */

use tracing::{debug, error, warn};

use crate::error::WfpError;
use crate::ffi::*;
use crate::session::Engine;

/// Represents an active WFP transaction.
///
/// Ensures atomicity when adding or modifying providers, sublayers, and filters.
/// If dropped before `commit()` is called, the transaction is automatically aborted.
pub struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl<'a> Transaction<'a> {
    /// Begins a new transaction on the given WFP engine.
    pub fn begin(engine: &'a Engine) -> Result<Self, WfpError> {
        if !engine.is_valid() {
            return Err(WfpError::EngineClosed);
        }

        debug!("Beginning WFP transaction on engine {:p}", engine.handle());
        let status = unsafe { FwpmTransactionBegin0(engine.handle(), 0) };
        if status != 0 {
            error!("FwpmTransactionBegin0 failed: 0x{:08x}", status);
            return Err(WfpError::Win32(status));
        }

        Ok(Self {
            engine,
            committed: false,
        })
    }

    /// Returns the engine reference associated with this transaction.
    pub fn engine(&self) -> &'a Engine {
        self.engine
    }

    /// Commits the active transaction.
    pub fn commit(mut self) -> Result<(), WfpError> {
        if self.committed {
            return Err(WfpError::AlreadyCommitted);
        }

        debug!("Committing WFP transaction on engine {:p}", self.engine.handle());
        let status = unsafe { FwpmTransactionCommit0(self.engine.handle()) };
        self.committed = true;

        if status != 0 {
            error!("FwpmTransactionCommit0 failed: 0x{:08x}, aborting", status);
            unsafe {
                let _ = FwpmTransactionAbort0(self.engine.handle());
            }
            return Err(WfpError::Win32(status));
        }

        debug!("WFP transaction committed successfully");
        Ok(())
    }

    /// Aborts the active transaction.
    pub fn abort(mut self) -> Result<(), WfpError> {
        if self.committed {
            return Err(WfpError::AlreadyCommitted);
        }

        warn!("Aborting WFP transaction on engine {:p}", self.engine.handle());
        let status = unsafe { FwpmTransactionAbort0(self.engine.handle()) };
        self.committed = true;

        if status != 0 {
            error!("FwpmTransactionAbort0 failed: 0x{:08x}", status);
            return Err(WfpError::Win32(status));
        }

        Ok(())
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        if !self.committed && self.engine.is_valid() {
            warn!("Transaction dropped without commit; automatically aborting");
            unsafe {
                let _ = FwpmTransactionAbort0(self.engine.handle());
            }
        }
    }
}

impl Engine {
    /// Executes a closure within an atomic WFP transaction.
    ///
    /// If the closure succeeds, the transaction is committed.
    /// If the closure returns an error or panics, the transaction is aborted.
    pub fn run_transaction<F, R, E>(&self, f: F) -> Result<R, E>
    where
        F: FnOnce(&Transaction) -> Result<R, E>,
        E: From<WfpError>,
    {
        let txn = Transaction::begin(self)?;
        let result = f(&txn)?;
        txn.commit()?;
        Ok(result)
    }
}
