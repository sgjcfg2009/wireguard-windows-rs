use std::io::{Read, Write};

use crate::error::IpcError;
use crate::framed::FramedPipe;
use crate::protocol::{
    DownloadProgress, IpcNotification, IpcRequest, IpcRequestRef, IpcResponse, Tunnel,
    TunnelConfig, TunnelState, UpdateState,
};

#[cold]
fn unexpected_response(other: IpcResponse) -> IpcError {
    IpcError::InvalidMessage(format!("unexpected response: {other:?}"))
}

#[inline]
fn map_unit_response(res: Result<(), String>) -> Result<(), IpcError> {
    res.map_err(IpcError::Server)
}

/// High-level IPC client for issuing commands to the WireGuard Manager service.
pub struct IpcClient<R, W> {
    pipe: FramedPipe<R, W>,
}

impl<R: Read, W: Write> IpcClient<R, W> {
    /// Creates a new `IpcClient` wrapping the given reader and writer.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            pipe: FramedPipe::new(reader, writer),
        }
    }

    fn call_ref<T: serde::Serialize>(&mut self, request: &T) -> Result<IpcResponse, IpcError> {
        self.pipe.send(request)?;
        self.pipe.recv()
    }

    /// Sends an IPC request and waits for the corresponding response.
    pub fn call(&mut self, request: IpcRequest) -> Result<IpcResponse, IpcError> {
        self.call_ref(&request)
    }

    /// Retrieves stored configuration for a named tunnel.
    pub fn stored_config(&mut self, tunnel_name: &str) -> Result<TunnelConfig, IpcError> {
        match self.call_ref(&IpcRequestRef::StoredConfig { tunnel_name })? {
            IpcResponse::StoredConfig(res) => res.map_err(IpcError::Server),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Retrieves runtime configuration from the active driver adapter.
    pub fn runtime_config(&mut self, tunnel_name: &str) -> Result<TunnelConfig, IpcError> {
        match self.call_ref(&IpcRequestRef::RuntimeConfig { tunnel_name })? {
            IpcResponse::RuntimeConfig(res) => res.map_err(IpcError::Server),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Starts a tunnel service by name.
    pub fn start(&mut self, tunnel_name: &str) -> Result<(), IpcError> {
        match self.call_ref(&IpcRequestRef::Start { tunnel_name })? {
            IpcResponse::Start(res) => map_unit_response(res),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Stops a tunnel service by name.
    pub fn stop(&mut self, tunnel_name: &str) -> Result<(), IpcError> {
        match self.call_ref(&IpcRequestRef::Stop { tunnel_name })? {
            IpcResponse::Stop(res) => map_unit_response(res),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Waits until a tunnel service has fully stopped.
    pub fn wait_for_stop(&mut self, tunnel_name: &str) -> Result<(), IpcError> {
        match self.call_ref(&IpcRequestRef::WaitForStop { tunnel_name })? {
            IpcResponse::WaitForStop(res) => map_unit_response(res),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Deletes a tunnel configuration from disk.
    pub fn delete(&mut self, tunnel_name: &str) -> Result<(), IpcError> {
        match self.call_ref(&IpcRequestRef::Delete { tunnel_name })? {
            IpcResponse::Delete(res) => map_unit_response(res),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Queries the operational state of a tunnel.
    pub fn state(&mut self, tunnel_name: &str) -> Result<TunnelState, IpcError> {
        match self.call_ref(&IpcRequestRef::State { tunnel_name })? {
            IpcResponse::State(res) => res.map_err(IpcError::Server),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Queries the global aggregated state of all tunnels.
    pub fn global_state(&mut self) -> Result<TunnelState, IpcError> {
        match self.call(IpcRequest::GlobalState)? {
            IpcResponse::GlobalState(state) => Ok(state),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Creates or updates a tunnel configuration.
    pub fn create(&mut self, config: TunnelConfig) -> Result<Tunnel, IpcError> {
        match self.call(IpcRequest::Create { config })? {
            IpcResponse::Create(res) => res.map_err(IpcError::Server),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Lists all installed tunnels.
    pub fn list_tunnels(&mut self) -> Result<Vec<Tunnel>, IpcError> {
        match self.call(IpcRequest::ListTunnels)? {
            IpcResponse::ListTunnels(res) => res.map_err(IpcError::Server),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Requests that the manager daemon exit.
    pub fn quit(&mut self, stop_tunnels_on_quit: bool) -> Result<bool, IpcError> {
        match self.call(IpcRequest::Quit { stop_tunnels_on_quit })? {
            IpcResponse::Quit(res) => res.map_err(IpcError::Server),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Checks the software update status.
    pub fn update_state(&mut self) -> Result<UpdateState, IpcError> {
        match self.call(IpcRequest::UpdateState)? {
            IpcResponse::UpdateState(state) => Ok(state),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }

    /// Requests the manager to download and launch the latest software update.
    pub fn trigger_update(&mut self) -> Result<(), IpcError> {
        match self.call(IpcRequest::TriggerUpdate)? {
            IpcResponse::TriggerUpdate(res) => map_unit_response(res),
            IpcResponse::Error(err) => Err(IpcError::Server(err)),
            other => Err(unexpected_response(other)),
        }
    }
}

pub type TunnelChangeCallback = Box<dyn Fn(&str, TunnelState, TunnelState, Option<&str>) + Send + Sync>;
pub type TunnelsChangeCallback = Box<dyn Fn() + Send + Sync>;
pub type ManagerStoppingCallback = Box<dyn Fn() + Send + Sync>;
pub type UpdateFoundCallback = Box<dyn Fn(UpdateState) + Send + Sync>;
pub type UpdateProgressCallback = Box<dyn Fn(&DownloadProgress) + Send + Sync>;

/// Dispatcher for UI event notifications received over the events pipe.
pub struct NotificationListener<R> {
    reader: crate::framed::FramedReader<R>,
    on_tunnel_change: Vec<TunnelChangeCallback>,
    on_tunnels_change: Vec<TunnelsChangeCallback>,
    on_manager_stopping: Vec<ManagerStoppingCallback>,
    on_update_found: Vec<UpdateFoundCallback>,
    on_update_progress: Vec<UpdateProgressCallback>,
}

impl<R: Read> NotificationListener<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: crate::framed::FramedReader::new(reader),
            on_tunnel_change: Vec::new(),
            on_tunnels_change: Vec::new(),
            on_manager_stopping: Vec::new(),
            on_update_found: Vec::new(),
            on_update_progress: Vec::new(),
        }
    }

    pub fn register_tunnel_change(&mut self, cb: TunnelChangeCallback) {
        self.on_tunnel_change.push(cb);
    }

    pub fn register_tunnels_change(&mut self, cb: TunnelsChangeCallback) {
        self.on_tunnels_change.push(cb);
    }

    pub fn register_manager_stopping(&mut self, cb: ManagerStoppingCallback) {
        self.on_manager_stopping.push(cb);
    }

    pub fn register_update_found(&mut self, cb: UpdateFoundCallback) {
        self.on_update_found.push(cb);
    }

    pub fn register_update_progress(&mut self, cb: UpdateProgressCallback) {
        self.on_update_progress.push(cb);
    }

    /// Reads the next notification from the pipe and dispatches it to registered callbacks.
    pub fn process_one(&mut self) -> Result<IpcNotification, IpcError> {
        let notification: IpcNotification = self.reader.recv()?;
        self.dispatch(&notification);
        Ok(notification)
    }

    /// Dispatches a notification to all registered callbacks.
    pub fn dispatch(&self, notification: &IpcNotification) {
        match notification {
            IpcNotification::TunnelChange {
                tunnel,
                state,
                global_state,
                error,
            } => {
                for cb in &self.on_tunnel_change {
                    cb(tunnel, *state, *global_state, error.as_deref());
                }
            }
            IpcNotification::TunnelsChange => {
                for cb in &self.on_tunnels_change {
                    cb();
                }
            }
            IpcNotification::ManagerStopping => {
                for cb in &self.on_manager_stopping {
                    cb();
                }
            }
            IpcNotification::UpdateFound { state } => {
                for cb in &self.on_update_found {
                    cb(*state);
                }
            }
            IpcNotification::UpdateProgress(dp) => {
                for cb in &self.on_update_progress {
                    cb(dp);
                }
            }
        }
    }

    /// Runs a loop continuously processing incoming notifications until the pipe closes.
    pub fn run(&mut self) -> Result<(), IpcError> {
        loop {
            match self.process_one() {
                Ok(_) => {}
                Err(IpcError::PipeBroken) => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }
}
