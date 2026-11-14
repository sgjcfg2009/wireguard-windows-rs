use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use crate::error::IpcError;
use crate::framed::{encode_json_frame, FramedReader, FramedWriter};
use crate::protocol::{
    DownloadProgress, IpcNotification, IpcNotificationRef, IpcRequest, IpcResponse, Tunnel,
    TunnelConfig, TunnelState, UpdateState,
};

/// Trait defining the core backend operations executed by the WireGuard Manager service.
pub trait ManagerHandler: Send + Sync {
    fn stored_config(&self, tunnel_name: &str) -> Result<TunnelConfig, String>;
    fn runtime_config(&self, tunnel_name: &str) -> Result<TunnelConfig, String>;
    fn start(&self, tunnel_name: &str) -> Result<(), String>;
    fn stop(&self, tunnel_name: &str) -> Result<(), String>;
    fn wait_for_stop(&self, tunnel_name: &str) -> Result<(), String>;
    fn delete(&self, tunnel_name: &str) -> Result<(), String>;
    fn state(&self, tunnel_name: &str) -> Result<TunnelState, String>;
    fn global_state(&self) -> TunnelState;
    fn create(&self, config: TunnelConfig) -> Result<Tunnel, String>;
    fn list_tunnels(&self) -> Result<Vec<Tunnel>, String>;
    fn quit(&self, stop_tunnels_on_quit: bool) -> Result<bool, String>;
    fn update_state(&self) -> UpdateState;
    fn trigger_update(&self) -> Result<(), String>;
}

/// Server session handling request/response dispatching on a single IPC connection.
pub struct IpcServerSession<R, W, H> {
    reader: FramedReader<R>,
    writer: FramedWriter<W>,
    handler: Arc<H>,
}

impl<R: Read, W: Write, H: ManagerHandler> IpcServerSession<R, W, H> {
    pub fn new(reader: R, writer: W, handler: Arc<H>) -> Self {
        Self {
            reader: FramedReader::new(reader),
            writer: FramedWriter::new(writer),
            handler,
        }
    }

    /// Serves a single request/response cycle. Returns Ok(false) on EOF / pipe broken.
    pub fn serve_one(&mut self) -> Result<bool, IpcError> {
        let request: IpcRequest = match self.reader.recv() {
            Ok(req) => req,
            Err(IpcError::PipeBroken) => return Ok(false),
            Err(e) => return Err(e),
        };

        let response = match request {
            IpcRequest::StoredConfig { tunnel_name } => {
                IpcResponse::StoredConfig(self.handler.stored_config(&tunnel_name))
            }
            IpcRequest::RuntimeConfig { tunnel_name } => {
                IpcResponse::RuntimeConfig(self.handler.runtime_config(&tunnel_name))
            }
            IpcRequest::Start { tunnel_name } => {
                IpcResponse::Start(self.handler.start(&tunnel_name))
            }
            IpcRequest::Stop { tunnel_name } => {
                IpcResponse::Stop(self.handler.stop(&tunnel_name))
            }
            IpcRequest::WaitForStop { tunnel_name } => {
                IpcResponse::WaitForStop(self.handler.wait_for_stop(&tunnel_name))
            }
            IpcRequest::Delete { tunnel_name } => {
                IpcResponse::Delete(self.handler.delete(&tunnel_name))
            }
            IpcRequest::State { tunnel_name } => {
                IpcResponse::State(self.handler.state(&tunnel_name))
            }
            IpcRequest::GlobalState => {
                IpcResponse::GlobalState(self.handler.global_state())
            }
            IpcRequest::Create { config } => {
                IpcResponse::Create(self.handler.create(config))
            }
            IpcRequest::ListTunnels => {
                IpcResponse::ListTunnels(self.handler.list_tunnels())
            }
            IpcRequest::Quit { stop_tunnels_on_quit } => {
                IpcResponse::Quit(self.handler.quit(stop_tunnels_on_quit))
            }
            IpcRequest::UpdateState => {
                IpcResponse::UpdateState(self.handler.update_state())
            }
            IpcRequest::TriggerUpdate => {
                IpcResponse::TriggerUpdate(self.handler.trigger_update())
            }
        };

        self.writer.send(&response)?;
        Ok(true)
    }

    /// Runs the request loop until the client disconnects or an error occurs.
    pub fn serve(&mut self) -> Result<(), IpcError> {
        while self.serve_one()? {}
        Ok(())
    }
}

struct BroadcasterState<W> {
    subscribers: Vec<W>,
    frame_buf: Vec<u8>,
}

impl<W> Default for BroadcasterState<W> {
    fn default() -> Self {
        Self {
            subscribers: Vec::new(),
            frame_buf: Vec::with_capacity(256),
        }
    }
}

/// Thread-safe broadcaster for dispatching asynchronous notifications to connected UI clients.
#[derive(Default)]
pub struct NotificationBroadcaster<W> {
    state: Mutex<BroadcasterState<W>>,
}

impl<W: Write + Send + 'static> NotificationBroadcaster<W> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BroadcasterState::default()),
        }
    }

    /// Adds a new subscriber writer to receive event notifications.
    pub fn add_subscriber(&self, writer: W) {
        let mut state = self.state.lock().unwrap();
        state.subscribers.push(writer);
    }

    fn broadcast_serializable<T: serde::Serialize>(&self, notification: &T) {
        let mut state = self.state.lock().unwrap();
        let BroadcasterState {
            subscribers,
            frame_buf,
        } = &mut *state;
        if subscribers.is_empty() {
            return;
        }
        if encode_json_frame(notification, frame_buf).is_err() {
            return;
        }
        subscribers.retain_mut(|writer| writer.write_all(frame_buf).is_ok() && writer.flush().is_ok());
    }

    /// Broadcasts a notification to all subscribers, pruning any dead connections.
    pub fn broadcast(&self, notification: &IpcNotification) {
        self.broadcast_serializable(notification);
    }

    /// Notifies that a tunnel operational state or error changed.
    pub fn notify_tunnel_change(
        &self,
        tunnel: &str,
        state: TunnelState,
        global_state: TunnelState,
        error: Option<&str>,
    ) {
        self.broadcast_serializable(&IpcNotificationRef::TunnelChange {
            tunnel,
            state,
            global_state,
            error,
        });
    }

    /// Notifies that the tunnel list changed.
    pub fn notify_tunnels_change(&self) {
        self.broadcast(&IpcNotification::TunnelsChange);
    }

    /// Notifies that the manager service is stopping.
    pub fn notify_manager_stopping(&self) {
        self.broadcast(&IpcNotification::ManagerStopping);
    }

    /// Notifies that a new software update is available.
    pub fn notify_update_found(&self, state: UpdateState) {
        self.broadcast(&IpcNotification::UpdateFound { state });
    }

    /// Notifies software update download progress.
    pub fn notify_update_progress(&self, progress: &DownloadProgress) {
        self.broadcast_serializable(&IpcNotificationRef::UpdateProgress(progress));
    }
}
