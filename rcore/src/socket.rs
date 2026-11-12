use anyhow::Result;
use std::os::fd::AsFd;

#[derive(Default)]
pub struct Options {
    pub interface: String,
    pub tcp_fast_open: Option<bool>,
}

impl Options {
    pub fn apply(&self, _socket: &impl AsFd, tcp: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use anyhow::{Context, ensure};
            use std::{ffi::CString, io, os::fd::AsRawFd};

            let fd = _socket.as_fd().as_raw_fd();
            if !self.interface.is_empty() {
                ensure!(
                    self.interface.len() < libc::IFNAMSIZ,
                    "socket interface name is too long"
                );
                let interface = CString::new(self.interface.as_bytes())
                    .context("socket interface name contains a NUL byte")?;
                // SAFETY: interface holds the NUL-terminated name for the declared length.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        interface.as_ptr().cast(),
                        interface.as_bytes_with_nul().len() as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error()).with_context(|| {
                        format!(
                            "failed to bind outbound socket to interface {:?}",
                            self.interface
                        )
                    });
                }
            }
            if tcp && let Some(enabled) = self.tcp_fast_open {
                let value = libc::c_int::from(enabled);
                // SAFETY: value is a valid integer buffer of the declared length.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_FASTOPEN_CONNECT,
                        (&value as *const libc::c_int).cast(),
                        std::mem::size_of_val(&value) as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error())
                        .context("failed to set outbound TCP_FASTOPEN_CONNECT");
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::ensure!(
            self.interface.is_empty() && (!tcp || self.tcp_fast_open.is_none()),
            "outbound interface and TCP Fast Open socket options require Linux"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn absent_options_leave_sockets_usable() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        Options::default().apply(&socket, false).unwrap();
        assert!(socket.local_addr().unwrap().ip().is_loopback());
    }

    #[test]
    fn tcp_fast_open_is_ignored_for_udp() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        Options {
            tcp_fast_open: Some(true),
            ..Options::default()
        }
        .apply(&socket, false)
        .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_rejects_requested_options() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        for options in [
            Options {
                interface: "lo".into(),
                ..Options::default()
            },
            Options {
                tcp_fast_open: Some(true),
                ..Options::default()
            },
            Options {
                tcp_fast_open: Some(false),
                ..Options::default()
            },
        ] {
            let error = options.apply(&socket, true).unwrap_err();
            assert!(error.to_string().contains("Linux"));
        }
    }

    #[cfg(target_os = "linux")]
    fn bound_device(socket: &impl AsFd) -> Vec<u8> {
        use std::os::fd::AsRawFd;
        let mut device = [0u8; libc::IFNAMSIZ];
        let mut length = device.len() as libc::socklen_t;
        // SAFETY: device and length are writable buffers of the declared sizes.
        let result = unsafe {
            libc::getsockopt(
                socket.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                device.as_mut_ptr().cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        device[..length as usize]
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn binds_tcp_and_udp_to_requested_device() {
        let options = Options {
            interface: "lo".into(),
            ..Options::default()
        };
        let tcp = tokio::net::TcpSocket::new_v4().unwrap();
        options.apply(&tcp, true).unwrap();
        assert_eq!(bound_device(&tcp), b"lo");
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        options.apply(&udp, false).unwrap();
        assert_eq!(bound_device(&udp), b"lo");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_interfaces_fail_closed() {
        for interface in ["no-such-device", "lo\0missing", "lo012345678901234567890"] {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let options = Options {
                interface: interface.into(),
                ..Options::default()
            };
            assert!(
                options.apply(&socket, false).is_err(),
                "accepted {interface:?}"
            );
            assert!(bound_device(&socket).is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enables_and_disables_tcp_fast_open_connect() {
        use std::os::fd::AsRawFd;
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        for (enabled, expected) in [(true, 1), (false, 0)] {
            Options {
                tcp_fast_open: Some(enabled),
                ..Options::default()
            }
            .apply(&socket, true)
            .unwrap();
            let mut value: libc::c_int = -1;
            let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
            // SAFETY: value and length are writable buffers of the declared sizes.
            let result = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_FASTOPEN_CONNECT,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut length,
                )
            };
            assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
            assert_eq!(value, expected);
        }
    }
}
