//! Linux splice(2) for Vision's direct downlink, as Go's net.TCPConn.ReadFrom does it
//! (internal/poll.Splice: a non-blocking pipe sized to 1 MiB, drained from the source, then
//! pumped into the destination), so the bytes never pass through the process.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};
use tokio::{io::Interest, net::TcpStream};

/// internal/poll maxSpliceSize.
const MAX_SPLICE: usize = 1 << 20;

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills both descriptors on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned here.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // Like Go, a failed resize just keeps the default pipe size.
    // SAFETY: plain fcntl on an owned descriptor.
    unsafe { libc::fcntl(r.as_raw_fd(), libc::F_SETPIPE_SZ, MAX_SPLICE as libc::c_int) };
    Ok((r, w))
}

fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    loop {
        // SAFETY: both descriptors stay open for the call; null offsets mean "current position".
        let n = unsafe {
            libc::splice(
                from,
                std::ptr::null_mut(),
                to,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_NONBLOCK,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Moves `from`'s bytes into `to` until `from` reaches EOF. Returns the bytes moved, also on
/// error, as Go adds them to the stats either way.
pub async fn copy(from: &TcpStream, to: &TcpStream) -> (u64, io::Result<()>) {
    let (r, w) = match pipe() {
        Ok(pipe) => pipe,
        Err(error) => return (0, Err(error)),
    };
    let mut moved = 0u64;
    loop {
        // spliceDrain: wait until the source is readable, then fill the empty pipe.
        let filled = loop {
            if let Err(error) = from.readable().await {
                return (moved, Err(error));
            }
            match from.try_io(Interest::READABLE, || {
                splice(from.as_raw_fd(), w.as_raw_fd(), MAX_SPLICE)
            }) {
                Ok(n) => break n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return (moved, Err(error)),
            }
        };
        if filled == 0 {
            return (moved, Ok(()));
        }
        // splicePump: empty the pipe into the destination.
        let mut left = filled;
        while left > 0 {
            if let Err(error) = to.writable().await {
                return (moved, Err(error));
            }
            match to.try_io(Interest::WRITABLE, || {
                splice(r.as_raw_fd(), to.as_raw_fd(), left)
            }) {
                Ok(0) => return (moved, Err(io::ErrorKind::WriteZero.into())),
                Ok(n) => {
                    left -= n;
                    moved += n as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return (moved, Err(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn splices_a_large_stream_and_counts_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let data: Vec<u8> = (0..5_000_000u32).map(|i| (i % 251) as u8).collect();
        // source <- writer, destination -> reader
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(&sent).await.unwrap();
        });
        let (from, _) = listener.accept().await.unwrap();
        let reader_task = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            got
        });
        let (to, _) = listener.accept().await.unwrap();
        let (moved, result) = super::copy(&from, &to).await;
        result.unwrap();
        writer.await.unwrap();
        drop(to);
        assert_eq!(moved, data.len() as u64);
        assert_eq!(reader_task.await.unwrap(), data);
    }
}
