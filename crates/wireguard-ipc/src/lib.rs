//! Production-grade Win32 Inter-Process Communication (IPC) for WireGuard Windows in 100% Rust.
//!
//! Provides:
//! - Named pipes server & client with strict Win32 security descriptors (`O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`).
//! - Anonymous pipe creation and inheritance control for UI/Manager process communication.
//! - Strongly-typed message framing and serialization over pipes.
//! - Complete WireGuard Manager IPC protocol (tunnel queries, controls, configuration, and UI notifications).

pub mod client;
pub mod error;
pub mod framed;
pub mod handle;
pub mod named;
pub mod protocol;
pub mod security;
pub mod server;
pub mod unnamed;

// Re-exports for convenient top-level access
pub use client::{IpcClient, NotificationListener, TunnelChangeCallback, TunnelsChangeCallback};
pub use error::IpcError;
pub use framed::{
    read_frame, recv_json, send_json, write_frame, FramedPipe, FramedReader, FramedWriter,
    MAX_FRAME_SIZE,
};
pub use handle::PipeHandle;
pub use named::{
    normalize_pipe_name, NamedPipeClient, NamedPipeServer, DEFAULT_PIPE_BUFFER_SIZE,
    DEFAULT_PIPE_TIMEOUT_MS, GENERIC_READ, GENERIC_WRITE, PIPE_ACCESS_DUPLEX,
};
pub use protocol::{
    DownloadProgress, IpcNotification, IpcRequest, IpcResponse, Key, Tunnel, TunnelConfig,
    TunnelState, UpdateState,
};
pub use security::{SecurityDescriptor, STRICT_PIPE_SDDL};
pub use server::{IpcServerSession, ManagerHandler, NotificationBroadcaster};
pub use unnamed::{
    AnonymousPipe, ManagerUiPipes, UiChildHandles, UiClientPipes, DEFAULT_ANONYMOUS_PIPE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    #[test]
    fn test_strict_security_descriptor() {
        let sd = SecurityDescriptor::strict().expect("failed to create strict security descriptor");
        assert!(!sd.as_ptr().is_null());

        let sa = sd.to_security_attributes(false);
        assert_eq!(sa.bInheritHandle, 0);
        assert_eq!(sa.lpSecurityDescriptor, sd.as_ptr());

        let sa_inherit = sd.to_security_attributes(true);
        assert_eq!(sa_inherit.bInheritHandle, 1);
    }

    #[test]
    fn test_anonymous_pipe_transfer() {
        let (mut reader, mut writer) =
            AnonymousPipe::create_pair(false, false, 0).expect("failed to create pipe pair");

        let msg = b"Hello from WireGuard Windows Rust IPC!";
        writer.write_all(msg).expect("failed to write to pipe");
        writer.flush().expect("failed to flush");

        let mut buf = vec![0u8; msg.len()];
        reader.read_exact(&mut buf).expect("failed to read from pipe");
        assert_eq!(&buf, msg);
    }

    #[test]
    fn test_framed_json_messages() {
        let (reader, writer) =
            AnonymousPipe::create_pair(false, false, 0).expect("failed to create pipe pair");

        let mut framed_pipe = FramedPipe::new(reader, writer);

        let req = IpcRequest::Start {
            tunnel_name: "wg0".to_string(),
        };

        framed_pipe.send(&req).expect("failed to send frame");

        let received: IpcRequest = framed_pipe.recv().expect("failed to receive frame");
        assert_eq!(received, req);
    }

    #[test]
    fn test_manager_ui_pipes_setup() {
        let pipes = ManagerUiPipes::create().expect("failed to create manager-ui pipes");
        let child_handles = pipes.extract_child_handles();

        let raw_slice = child_handles.as_handle_slice();
        assert!(!raw_slice[0].is_null());
        assert!(!raw_slice[1].is_null());
        assert!(!raw_slice[2].is_null());

        let cmdline = child_handles.to_cmdline_args();
        assert!(!cmdline[0].is_empty());
        assert!(!cmdline[1].is_empty());
        assert!(!cmdline[2].is_empty());

        let (mgr_r, mgr_w, mgr_ev) = pipes.close_ui_handles();
        assert!(!mgr_r.is_invalid());
        assert!(!mgr_w.is_invalid());
        assert!(!mgr_ev.is_invalid());
    }

    struct MockManagerHandler {
        running: AtomicBool,
    }

    impl ManagerHandler for MockManagerHandler {
        fn stored_config(&self, tunnel_name: &str) -> Result<TunnelConfig, String> {
            Ok(TunnelConfig::new(tunnel_name))
        }
        fn runtime_config(&self, tunnel_name: &str) -> Result<TunnelConfig, String> {
            Ok(TunnelConfig::new(tunnel_name))
        }
        fn start(&self, _tunnel_name: &str) -> Result<(), String> {
            self.running.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn stop(&self, _tunnel_name: &str) -> Result<(), String> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn wait_for_stop(&self, _tunnel_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn delete(&self, _tunnel_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn state(&self, _tunnel_name: &str) -> Result<TunnelState, String> {
            if self.running.load(Ordering::SeqCst) {
                Ok(TunnelState::Started)
            } else {
                Ok(TunnelState::Stopped)
            }
        }
        fn global_state(&self) -> TunnelState {
            if self.running.load(Ordering::SeqCst) {
                TunnelState::Started
            } else {
                TunnelState::Stopped
            }
        }
        fn create(&self, config: TunnelConfig) -> Result<Tunnel, String> {
            Ok(Tunnel::new(config.name))
        }
        fn list_tunnels(&self) -> Result<Vec<Tunnel>, String> {
            Ok(vec![Tunnel::new("wg-test")])
        }
        fn quit(&self, _stop_tunnels_on_quit: bool) -> Result<bool, String> {
            Ok(false)
        }
        fn update_state(&self) -> UpdateState {
            UpdateState::FoundUpdate
        }
        fn trigger_update(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_client_server_request_response_cycle() {
        let (server_reader, client_writer) =
            AnonymousPipe::create_pair(false, false, 0).expect("pipe pair 1");
        let (client_reader, server_writer) =
            AnonymousPipe::create_pair(false, false, 0).expect("pipe pair 2");

        let handler = Arc::new(MockManagerHandler {
            running: AtomicBool::new(false),
        });

        let server_handler = Arc::clone(&handler);
        let server_thread = thread::spawn(move || {
            let mut session =
                IpcServerSession::new(server_reader, server_writer, server_handler);
            session.serve().expect("server failed");
        });

        let mut client = IpcClient::new(client_reader, client_writer);

        // Test list tunnels
        let tunnels = client.list_tunnels().expect("list tunnels failed");
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].name, "wg-test");

        // Test initial state (Stopped)
        let state = client.state("wg-test").expect("state check failed");
        assert_eq!(state, TunnelState::Stopped);

        // Test start tunnel
        client.start("wg-test").expect("start tunnel failed");

        // Test state after start (Started)
        let state = client.state("wg-test").expect("state check failed");
        assert_eq!(state, TunnelState::Started);

        // Test global state
        let global = client.global_state().expect("global state failed");
        assert_eq!(global, TunnelState::Started);

        // Test stop tunnel
        client.stop("wg-test").expect("stop tunnel failed");
        let state = client.state("wg-test").expect("state check failed");
        assert_eq!(state, TunnelState::Stopped);

        // Close client so server exits
        drop(client);
        server_thread.join().expect("server thread panicked");
    }

    #[test]
    fn test_notification_broadcasting() {
        let (events_reader, events_writer) =
            AnonymousPipe::create_pair(false, false, 0).expect("events pipe");

        let broadcaster = NotificationBroadcaster::new();
        broadcaster.add_subscriber(events_writer);

        let mut listener = NotificationListener::new(events_reader);

        let changed_tunnel = Arc::new(Mutex::new(String::new()));
        let changed_tunnel_clone = Arc::clone(&changed_tunnel);

        listener.register_tunnel_change(Box::new(move |tunnel, state, _, _| {
            let mut val = changed_tunnel_clone.lock().unwrap();
            *val = format!("{}:{:?}", tunnel, state);
        }));

        broadcaster.notify_tunnel_change("wg0", TunnelState::Started, TunnelState::Started, None);

        let notif = listener.process_one().expect("failed to process notification");
        assert!(matches!(notif, IpcNotification::TunnelChange { .. }));

        let recorded = changed_tunnel.lock().unwrap();
        assert_eq!(*recorded, "wg0:Started");
    }

    fn run_named_pipe_test(server: NamedPipeServer, pipe_name: String) {
        let client_thread = thread::spawn(move || {
            NamedPipeClient::connect(&pipe_name, Some(3000))
        });

        server.wait_for_connection().expect("server wait failed");
        let mut client_handle = client_thread.join().expect("client thread panicked").expect("client connect failed");

        let mut server_handle = server.into_handle();
        let msg = b"named pipe test payload";
        client_handle.write_all(msg).expect("write failed");
        let mut buf = vec![0u8; msg.len()];
        server_handle.read_exact(&mut buf).expect("read failed");
        assert_eq!(&buf, msg);
    }

    #[test]
    fn test_named_pipe_creation_and_communication() {
        let pipe_name = format!(r"\\.\pipe\wireguard-ipc-test-{}", std::process::id());

        // In user test mode (non-SYSTEM), O:SY returns 1307 (ERROR_INVALID_OWNER).
        // If running as SYSTEM (e.g. in service), STRICT_PIPE_SDDL succeeds directly.
        match NamedPipeServer::create_with_sddl(&pipe_name, STRICT_PIPE_SDDL, false) {
            Ok(server) => {
                run_named_pipe_test(server, pipe_name);
            }
            Err(IpcError::Win32(1307, _)) => {
                // Verified that O:SY requires SYSTEM privileges; test communication with user-level DACL
                let sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)";
                let server = NamedPipeServer::create_with_sddl(&pipe_name, sddl, false)
                    .expect("failed to create named pipe server with test DACL");
                run_named_pipe_test(server, pipe_name);
            }
            Err(e) => panic!("unexpected pipe error: {:?}", e),
        }
    }
}
