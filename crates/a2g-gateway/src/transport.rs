//! Length-prefixed CBOR transport framing (P4).
//!
//! Replaces the newline-delimited JSON wire format with a binary framing
//! scheme that is more compact, self-delimiting, and amenable to future
//! streaming or batching.
//!
//! ## Frame layout
//!
//! ```text
//! ┌───────────────────────┬─────────────────────────────────┐
//! │  length (4 B, BE u32) │  CBOR-serialized payload (N B)  │
//! └───────────────────────┴─────────────────────────────────┘
//! ```
//!
//! - **Length prefix**: big-endian `u32` — byte count of the CBOR body.
//!   Frames larger than `MAX_FRAME_BYTES` are rejected on read.
//! - **Payload**: standard CBOR produced by [`ciborium`], using the same
//!   `serde` derive attributes as the JSON codec.  The JSON wire format is
//!   no longer used for transport (though the JSON `Serialize`/`Deserialize`
//!   impls are retained for diagnostics and the demo key file).
//!
//! ## Backward compatibility
//!
//! The newline-delimited JSON path is kept alongside this module for the
//! `GatewayHandle::start_json()` test helper so that existing snapshots of
//! the gateway test harness are not broken.  New deployments use `write_frame`
//! / `read_frame` exclusively.

use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Read, Write};

/// Maximum accepted CBOR frame size (8 MiB). Frames larger than this are
/// rejected before allocation to prevent memory exhaustion on malformed input.
pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// Encode `value` to CBOR and write it as a length-prefixed frame to `w`.
pub fn write_frame<W, T>(w: &mut W, value: &T) -> io::Result<()>
where
    W: Write,
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = buf.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&buf)?;
    w.flush()
}

/// Read a length-prefixed CBOR frame from `r` and decode it as `T`.
///
/// Returns `Err(UnexpectedEof)` on a clean disconnect and other `io::Error`
/// variants on protocol violations.
pub fn read_frame<R, T>(r: &mut R) -> io::Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", len, MAX_FRAME_BYTES),
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    ciborium::from_reader(body.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        tag: String,
        value: i64,
    }

    #[test]
    fn test_round_trip() {
        let orig = Msg {
            tag: "hello".to_string(),
            value: 42,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &orig).unwrap();
        let mut cur = Cursor::new(&buf);
        let decoded: Msg = read_frame(&mut cur).unwrap();
        assert_eq!(orig, decoded);
    }

    #[test]
    fn test_frame_too_large_rejected() {
        let huge_len: u32 = MAX_FRAME_BYTES + 1;
        let mut buf = huge_len.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]); // partial body — should be rejected before reading
        let mut cur = Cursor::new(&buf);
        let result: io::Result<Msg> = read_frame(&mut cur);
        assert!(result.is_err(), "oversized frame must be rejected");
    }

    #[test]
    fn test_empty_stream_eof() {
        let buf: Vec<u8> = vec![];
        let mut cur = Cursor::new(&buf);
        let result: io::Result<Msg> = read_frame(&mut cur);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
