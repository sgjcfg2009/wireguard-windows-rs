use std::io::{self, Read, Write};
use serde::{de::DeserializeOwned, Serialize};

use crate::error::IpcError;

/// Maximum allowable frame size (16 MiB) to prevent memory exhaustion attacks.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Writes a length-prefixed raw frame into a writer.
///
/// Frame format:
/// `[ 4 bytes: length (big-endian u32) ][ payload: `length` bytes ]`
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), IpcError> {
    if payload.len() > MAX_FRAME_SIZE as usize {
        return Err(IpcError::Frame(format!(
            "payload size {} exceeds maximum allowed {}",
            payload.len(),
            MAX_FRAME_SIZE
        )));
    }

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// Reads a length-prefixed raw frame into a caller-provided reusable buffer.
pub fn read_frame_into<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> Result<(), IpcError> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::BrokenPipe => {
            return Err(IpcError::PipeBroken);
        }
        Err(e) => return Err(IpcError::Io(e)),
    }

    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_SIZE {
        return Err(IpcError::Frame(format!(
            "received frame size {} exceeds maximum {}",
            len, MAX_FRAME_SIZE
        )));
    }

    buf.resize(len as usize, 0);
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::BrokenPipe => {
            Err(IpcError::PipeBroken)
        }
        Err(e) => Err(IpcError::Io(e)),
    }
}

/// Reads a length-prefixed raw frame from a reader.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut buf = Vec::new();
    read_frame_into(reader, &mut buf)?;
    Ok(buf)
}

/// Serializes `value` into `scratch` as a length-prefixed frame (`[4-byte len][payload]`).
pub(crate) fn encode_json_frame<T: Serialize>(
    value: &T,
    scratch: &mut Vec<u8>,
) -> Result<(), IpcError> {
    scratch.clear();
    scratch.extend_from_slice(&[0u8; 4]);
    serde_json::to_writer(&mut *scratch, value)?;
    let payload_len = scratch.len() - 4;
    if payload_len > MAX_FRAME_SIZE as usize {
        return Err(IpcError::Frame(format!(
            "payload size {} exceeds maximum allowed {}",
            payload_len, MAX_FRAME_SIZE
        )));
    }
    scratch[..4].copy_from_slice(&(payload_len as u32).to_be_bytes());
    Ok(())
}

/// Serializes `value` using `scratch` (`[4-byte len][payload]`) and writes it in one syscall.
pub fn send_json_with_buf<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    scratch: &mut Vec<u8>,
) -> Result<(), IpcError> {
    encode_json_frame(value, scratch)?;
    writer.write_all(scratch)?;
    writer.flush()?;
    Ok(())
}

/// Serializes a value to JSON and writes it as a length-prefixed frame.
pub fn send_json<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), IpcError> {
    let mut scratch = Vec::with_capacity(256);
    send_json_with_buf(writer, value, &mut scratch)
}

/// Reads a length-prefixed frame and deserializes it from JSON using a reusable buffer.
pub fn recv_json_with_buf<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    scratch: &mut Vec<u8>,
) -> Result<T, IpcError> {
    read_frame_into(reader, scratch)?;
    let val = serde_json::from_slice(scratch)?;
    Ok(val)
}

/// Reads a length-prefixed frame and deserializes it from JSON.
pub fn recv_json<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, IpcError> {
    let mut scratch = Vec::new();
    recv_json_with_buf(reader, &mut scratch)
}

/// A bidirectional framed pipe stream that sends and receives strongly typed JSON messages.
pub struct FramedPipe<R, W> {
    reader: R,
    writer: W,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl<R: Read, W: Write> FramedPipe<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            read_buf: Vec::with_capacity(256),
            write_buf: Vec::with_capacity(256),
        }
    }

    pub fn send<T: Serialize>(&mut self, value: &T) -> Result<(), IpcError> {
        send_json_with_buf(&mut self.writer, value, &mut self.write_buf)
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T, IpcError> {
        recv_json_with_buf(&mut self.reader, &mut self.read_buf)
    }

    pub fn split(self) -> (FramedReader<R>, FramedWriter<W>) {
        (
            FramedReader {
                reader: self.reader,
                read_buf: self.read_buf,
            },
            FramedWriter {
                writer: self.writer,
                write_buf: self.write_buf,
            },
        )
    }
}

/// A unidirectional framed reader.
pub struct FramedReader<R> {
    reader: R,
    read_buf: Vec<u8>,
}

impl<R: Read> FramedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            read_buf: Vec::with_capacity(256),
        }
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T, IpcError> {
        recv_json_with_buf(&mut self.reader, &mut self.read_buf)
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// A unidirectional framed writer.
pub struct FramedWriter<W> {
    writer: W,
    write_buf: Vec<u8>,
}

impl<W: Write> FramedWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            write_buf: Vec::with_capacity(256),
        }
    }

    pub fn send<T: Serialize>(&mut self, value: &T) -> Result<(), IpcError> {
        send_json_with_buf(&mut self.writer, value, &mut self.write_buf)
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}
