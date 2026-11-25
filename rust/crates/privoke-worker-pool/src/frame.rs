//! The frame format every worker speaks: a 4-byte little-endian length, then that many payload bytes.
//!
//! The pool never looks inside a payload. The protocol on top (JSON for spaCy, protobuf for the runtime worker) is the
//! caller's [`crate::Protocol`].

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame either side accepts.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "frame too large")
}

/// Writes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(out: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| too_large())?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(too_large());
    }
    out.write_all(&len.to_le_bytes()).await?;
    out.write_all(payload).await?;
    out.flush().await
}

/// Reads one frame. A clean end of stream before the length is `UnexpectedEof`.
pub async fn read_frame<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len).await?;
    let len = frame_len(len)?;
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Blocking [`write_frame`], for workers written in Rust.
pub fn write_frame_sync(out: &mut impl io::Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| too_large())?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(too_large());
    }
    out.write_all(&len.to_le_bytes())?;
    out.write_all(payload)?;
    out.flush()
}

/// Blocking [`read_frame`], for workers written in Rust.
pub fn read_frame_sync(input: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len)?;
    let mut payload = vec![0u8; frame_len(len)?];
    input.read_exact(&mut payload)?;
    Ok(payload)
}

fn frame_len(raw: [u8; 4]) -> io::Result<usize> {
    let len = u32::from_le_bytes(raw) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {len} bytes exceeds the limit")));
    }
    Ok(len)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, b"{\"x\":1}").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), b"{\"x\":1}");
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_is_unexpected_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_le_bytes()).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn sync_frames_round_trip_and_match_the_async_format() {
        let mut wire = Vec::new();
        write_frame_sync(&mut wire, b"abc").unwrap();
        assert_eq!(wire, [3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(read_frame_sync(&mut wire.as_slice()).unwrap(), b"abc");
    }
}
