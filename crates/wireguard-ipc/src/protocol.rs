use serde::{Deserialize, Serialize};
pub use wireguard_types::{DownloadProgress, Key, TunnelConfig, TunnelState, UpdateState};

/// Representation of a tunnel in IPC queries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tunnel {
    pub name: String,
}

impl Tunnel {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Request sent from IPC client (e.g. UI or CLI) to IPC server (Manager service).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcRequest {
    /// Retrieve stored configuration for a tunnel by name.
    StoredConfig { tunnel_name: String },

    /// Retrieve runtime configuration for an active tunnel from driver.
    RuntimeConfig { tunnel_name: String },

    /// Start a tunnel by name.
    Start { tunnel_name: String },

    /// Stop a tunnel by name.
    Stop { tunnel_name: String },

    /// Wait until a tunnel service has fully stopped.
    WaitForStop { tunnel_name: String },

    /// Delete a tunnel configuration from disk.
    Delete { tunnel_name: String },

    /// Query the state of a specific tunnel.
    State { tunnel_name: String },

    /// Query the aggregate global state of all tunnels.
    GlobalState,

    /// Create or import a new tunnel configuration.
    Create { config: TunnelConfig },

    /// List all known tunnels.
    ListTunnels,

    /// Request manager termination, optionally stopping active tunnels.
    Quit { stop_tunnels_on_quit: bool },

    /// Query software update availability.
    UpdateState,

    /// Trigger software update download and installation.
    TriggerUpdate,
}

/// Response returned from IPC server to IPC client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcResponse {
    StoredConfig(Result<TunnelConfig, String>),
    RuntimeConfig(Result<TunnelConfig, String>),
    Start(Result<(), String>),
    Stop(Result<(), String>),
    WaitForStop(Result<(), String>),
    Delete(Result<(), String>),
    State(Result<TunnelState, String>),
    GlobalState(TunnelState),
    Create(Result<Tunnel, String>),
    ListTunnels(Result<Vec<Tunnel>, String>),
    Quit(Result<bool, String>),
    UpdateState(UpdateState),
    TriggerUpdate(Result<(), String>),
    Error(String),
}

/// Asynchronous notification broadcast from Manager service to connected UI clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcNotification {
    /// Notification that a tunnel's operational state or configuration changed.
    TunnelChange {
        tunnel: String,
        state: TunnelState,
        global_state: TunnelState,
        error: Option<String>,
    },

    /// Notification that the set of configured tunnels changed (added, deleted, renamed).
    TunnelsChange,

    /// Notification that the manager service is stopping.
    ManagerStopping,

    /// Notification that a new software update is available.
    UpdateFound { state: UpdateState },

    /// Download progress update during software update download.
    UpdateProgress(DownloadProgress),
}

/// Zero-allocation serialization view of `IpcRequest` for `&str`-based client calls.
#[derive(Serialize)]
#[serde(tag = "type", content = "payload")]
pub(crate) enum IpcRequestRef<'a> {
    StoredConfig { tunnel_name: &'a str },
    RuntimeConfig { tunnel_name: &'a str },
    Start { tunnel_name: &'a str },
    Stop { tunnel_name: &'a str },
    WaitForStop { tunnel_name: &'a str },
    Delete { tunnel_name: &'a str },
    State { tunnel_name: &'a str },
}

/// Zero-allocation serialization view of `IpcNotification` for server broadcasts.
#[derive(Serialize)]
#[serde(tag = "type", content = "payload")]
pub(crate) enum IpcNotificationRef<'a> {
    TunnelChange {
        tunnel: &'a str,
        state: TunnelState,
        global_state: TunnelState,
        error: Option<&'a str>,
    },
    UpdateProgress(&'a DownloadProgress),
}
