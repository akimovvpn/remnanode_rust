//! xtls-rprx-vision framing (server and client sides), ported from Xray-core v26.11.9
//! proxy/proxy.go.
//! SPDX-License-Identifier: MPL-2.0

use ring::rand::{SecureRandom, SystemRandom};
use std::{
    io,
    sync::{Arc, Mutex},
};

const BUFFER_SIZE: usize = 8192;
const MAX_CONTENT: usize = BUFFER_SIZE - 21;
const MAX_TLS_RECORD: usize = 18432;
pub type SharedState = Arc<Mutex<State>>;

pub struct Output {
    pub data: Vec<u8>,
    /// Switch this direction to the raw transport only after forwarding `data`.
    pub direct: bool,
}

pub struct State {
    packets_left: u8,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    client_prefix: Vec<u8>,
    server_hello: Vec<u8>,
    server_done: bool,
    /// Client side: the encoder carries the ClientHello and the decoder the ServerHello.
    client: bool,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            packets_left: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            client_prefix: Vec::new(),
            server_hello: Vec::new(),
            server_done: false,
            client: false,
        }
    }
    fn observe_decoded(&mut self, data: &[u8]) {
        if self.client {
            self.observe_server(data)
        } else {
            self.observe_client(data)
        }
    }
    fn observe_encoded(&mut self, data: &[u8]) {
        if self.client {
            self.observe_client(data)
        } else {
            self.observe_server(data)
        }
    }
    fn count_packet(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.packets_left = self.packets_left.saturating_sub(1);
        }
    }
    fn observe_client(&mut self, data: &[u8]) {
        self.count_packet(data);
        let take = (6 - self.client_prefix.len()).min(data.len());
        self.client_prefix.extend_from_slice(&data[..take]);
        if self.client_prefix.len() == 6 {
            self.is_tls |= self.client_prefix[..2] == [22, 3] && self.client_prefix[5] == 1;
        }
    }
    fn observe_server(&mut self, mut data: &[u8]) {
        self.count_packet(data);
        if self.server_done {
            return;
        }
        if self.server_hello.len() < 6 {
            let take = (6 - self.server_hello.len()).min(data.len());
            self.server_hello.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        if self.server_hello.len() < 6 {
            return;
        }
        let prefix = &self.server_hello;
        if prefix[..3] != [22, 3, 3] || prefix[5] != 2 {
            self.server_done = true;
            self.server_hello.clear();
            return;
        }
        self.is_tls = true;
        self.is_tls12_or_above = true;
        let length = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
        if !(4..=MAX_TLS_RECORD).contains(&length) {
            self.server_done = true;
            self.server_hello.clear();
            return;
        }
        let take = (length + 5 - self.server_hello.len()).min(data.len());
        self.server_hello.extend_from_slice(&data[..take]);
        if self.server_hello.len() < length + 5 {
            return;
        }
        self.enable_xtls = supports_direct(&self.server_hello[5..]);
        self.packets_left = 0;
        self.server_done = true;
        self.server_hello.clear();
    }
}

fn supports_direct(handshake: &[u8]) -> bool {
    if handshake.len() < 4 {
        return false;
    }
    let length =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    let Some(body) = handshake.get(4..4 + length) else {
        return false;
    };
    if body.len() < 38 || body[..2] != [3, 3] {
        return false;
    }
    let session_length = body[34] as usize;
    if session_length > 32 {
        return false;
    }
    let cipher_offset = 35 + session_length;
    let Some(fields) = body.get(cipher_offset..cipher_offset + 5) else {
        return false;
    };
    let cipher = u16::from_be_bytes([fields[0], fields[1]]);
    if !(0x1301..=0x1304).contains(&cipher) || fields[2] != 0 {
        return false;
    }
    let extension_length = u16::from_be_bytes([fields[3], fields[4]]) as usize;
    let Some(mut extensions) = body.get(cipher_offset + 5..) else {
        return false;
    };
    if extensions.len() != extension_length {
        return false;
    }
    let mut tls13 = false;
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return false;
        }
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let length = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        let Some(value) = extensions.get(4..4 + length) else {
            return false;
        };
        if kind == 43 {
            tls13 |= value == [3, 4];
        }
        extensions = &extensions[4 + length..];
    }
    tls13
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn locked(state: &SharedState) -> io::Result<std::sync::MutexGuard<'_, State>> {
    state
        .lock()
        .map_err(|_| io::Error::other("Vision state poisoned"))
}

pub struct Decoder {
    uuid: [u8; 16],
    state: SharedState,
    prefix_used: usize,
    frame_seen: bool,
    header: [u8; 5],
    header_used: usize,
    content_left: usize,
    padding_left: usize,
    command: u8,
    padding: bool,
}

impl Decoder {
    pub fn new(uuid: [u8; 16], state: SharedState) -> Self {
        Self {
            uuid,
            state,
            prefix_used: 0,
            frame_seen: false,
            header: [0; 5],
            header_used: 0,
            content_left: 0,
            padding_left: 0,
            command: 0,
            padding: true,
        }
    }
    pub fn decode(&mut self, mut bytes: &[u8]) -> io::Result<Output> {
        let mut out = Output {
            data: Vec::new(),
            direct: false,
        };
        while !bytes.is_empty() {
            if !self.padding {
                out.data.extend_from_slice(bytes);
                break;
            }
            if self.prefix_used < 16 {
                let take = (16 - self.prefix_used).min(bytes.len());
                if bytes[..take] != self.uuid[self.prefix_used..self.prefix_used + take] {
                    return Err(invalid("Vision UUID mismatch"));
                }
                self.prefix_used += take;
                bytes = &bytes[take..];
                continue;
            }
            if self.header_used < 5 {
                let take = (5 - self.header_used).min(bytes.len());
                self.header[self.header_used..self.header_used + take]
                    .copy_from_slice(&bytes[..take]);
                self.header_used += take;
                bytes = &bytes[take..];
                if self.header_used != 5 {
                    continue;
                }
                self.frame_seen = true;
                self.command = self.header[0];
                if self.command > 2 {
                    return Err(invalid("invalid Vision command"));
                }
                self.content_left = u16::from_be_bytes([self.header[1], self.header[2]]) as usize;
                self.padding_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            }
            let take = self.content_left.min(bytes.len());
            out.data.extend_from_slice(&bytes[..take]);
            self.content_left -= take;
            bytes = &bytes[take..];
            if self.content_left != 0 {
                continue;
            }
            let take = self.padding_left.min(bytes.len());
            self.padding_left -= take;
            bytes = &bytes[take..];
            if self.padding_left != 0 {
                continue;
            }
            self.header_used = 0;
            if self.command != 0 {
                self.padding = false;
                out.direct = self.command == 2;
            }
        }
        locked(&self.state)?.observe_decoded(&out.data);
        Ok(out)
    }
    /// Call at transport EOF to reject a partially received UUID or frame.
    pub fn finish(&self) -> io::Result<()> {
        if (self.prefix_used != 0 && (self.prefix_used != 16 || !self.frame_seen))
            || self.header_used != 0
            || self.content_left != 0
            || self.padding_left != 0
        {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Vision frame",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct RecordBoundary {
    header: [u8; 5],
    used: usize,
    remaining: usize,
    application: bool,
    invalid: bool,
}
impl RecordBoundary {
    fn observe(&mut self, mut data: &[u8]) -> bool {
        let mut completed_application = false;
        while !data.is_empty() && !self.invalid {
            if self.remaining != 0 {
                let take = self.remaining.min(data.len());
                self.remaining -= take;
                data = &data[take..];
                if self.remaining == 0 {
                    completed_application |= self.application;
                }
                continue;
            }
            let take = (5 - self.used).min(data.len());
            self.header[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used != 5 {
                continue;
            }
            self.used = 0;
            self.application = self.header[..3] == [23, 3, 3];
            self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            self.invalid = !matches!(self.header[0], 20..=23)
                || self.header[1] != 3
                || self.header[2] > 3
                || self.remaining == 0
                || self.remaining > MAX_TLS_RECORD;
        }
        completed_application && !self.invalid && self.used == 0 && self.remaining == 0
    }
}

pub struct Encoder {
    uuid: [u8; 16],
    state: SharedState,
    first: bool,
    padding: bool,
    records: RecordBoundary,
}
impl Encoder {
    pub fn new(uuid: [u8; 16], state: SharedState) -> Self {
        Self {
            uuid,
            state,
            first: true,
            padding: true,
            records: RecordBoundary::default(),
        }
    }
    pub fn encode(&mut self, bytes: &[u8]) -> io::Result<Output> {
        if !self.padding {
            return Ok(Output {
                data: bytes.to_vec(),
                direct: false,
            });
        }
        let complete_application = self.records.observe(bytes);
        let (long_padding, command) = {
            let mut state = locked(&self.state)?;
            state.observe_encoded(bytes);
            let command = if state.is_tls && complete_application {
                if state.enable_xtls { 2 } else { 1 }
            } else if !state.is_tls12_or_above && state.packets_left <= 1 {
                1
            } else {
                0
            };
            (state.is_tls || bytes.is_empty(), command)
        };
        let mut out = Vec::new();
        let chunks = bytes.len().div_ceil(MAX_CONTENT).max(1);
        for index in 0..chunks {
            let start = (index * MAX_CONTENT).min(bytes.len());
            let end = (start + MAX_CONTENT).min(bytes.len());
            let content = &bytes[start..end];
            let mut random = [0; 2];
            SystemRandom::new()
                .fill(&mut random)
                .map_err(|_| io::Error::other("Vision padding randomness failed"))?;
            let random = u16::from_be_bytes(random) as usize;
            let padding = if long_padding && content.len() < 900 {
                900 + random % 500 - content.len()
            } else {
                random % 256
            }
            .min(MAX_CONTENT - content.len());
            if self.first {
                out.extend_from_slice(&self.uuid);
                self.first = false;
            }
            out.push(if index + 1 == chunks { command } else { 0 });
            out.extend_from_slice(&(content.len() as u16).to_be_bytes());
            out.extend_from_slice(&(padding as u16).to_be_bytes());
            out.extend_from_slice(content);
            out.resize(out.len() + padding, 0);
        }
        if command != 0 {
            self.padding = false;
        }
        Ok(Output {
            data: out,
            direct: command == 2,
        })
    }
}

use crate::{tls13::DirectControl, transport::BoxIo};
use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Install after decoding the VLESS request; its two-byte response stays unframed.
pub fn wrap(
    io: BoxIo,
    payload: &[u8],
    uuid: [u8; 16],
    control: DirectControl,
) -> io::Result<(BoxIo, Vec<u8>)> {
    let state = Arc::new(Mutex::new(State::new()));
    let mut decoder = Decoder::new(uuid, state.clone());
    let initial = decoder.decode(payload)?;
    if initial.direct {
        control.read_direct();
    }
    Ok((
        Box::new(Io {
            inner: io,
            decoder,
            encoder: Encoder::new(uuid, state),
            control,
            read_pending: Vec::new(),
            read_offset: 0,
            write_pending: Vec::new(),
            write_offset: 0,
            write_direct: false,
            response_left: 2,
            response: None,
        }),
        initial.data,
    ))
}

/// Client side: `request` (the VLESS header) goes out unframed with the padded `first`
/// payload (an empty `first` is the long padding that hides the header); reads start with
/// the VLESS response header, then Vision frames.
pub fn client(
    io: BoxIo,
    uuid: [u8; 16],
    control: DirectControl,
    request: Vec<u8>,
    first: &[u8],
) -> io::Result<BoxIo> {
    let mut state = State::new();
    state.client = true;
    let state = Arc::new(Mutex::new(state));
    let mut encoder = Encoder::new(uuid, state.clone());
    let mut write_pending = request;
    let mut rest = first;
    let write_direct = loop {
        let take = MAX_CONTENT.min(rest.len());
        let encoded = encoder.encode(&rest[..take])?;
        write_pending.extend_from_slice(&encoded.data);
        rest = &rest[take..];
        if rest.is_empty() || encoded.direct {
            break encoded.direct;
        }
    };
    if !rest.is_empty() {
        // Bytes after a direct switch go out raw once the frame is flushed.
        return Err(io::Error::other(
            "Vision first payload spans a direct switch",
        ));
    }
    Ok(Box::new(Io {
        inner: io,
        decoder: Decoder::new(uuid, state),
        encoder,
        control,
        read_pending: Vec::new(),
        read_offset: 0,
        write_pending,
        write_offset: 0,
        write_direct,
        response_left: 0,
        response: Some(Vec::new()),
    }))
}

struct Io {
    inner: BoxIo,
    decoder: Decoder,
    encoder: Encoder,
    control: DirectControl,
    read_pending: Vec<u8>,
    read_offset: usize,
    write_pending: Vec<u8>,
    write_offset: usize,
    write_direct: bool,
    response_left: usize,
    /// Client side: the VLESS response header (version, addons) still being read.
    response: Option<Vec<u8>>,
}
impl Io {
    fn drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_pending.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_pending[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += written;
        }
        if self.write_direct {
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.control.write_direct();
            self.write_direct = false;
        }
        self.write_pending.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..16 {
            if self.read_offset < self.read_pending.len() {
                let take = out
                    .remaining()
                    .min(self.read_pending.len() - self.read_offset);
                out.put_slice(&self.read_pending[self.read_offset..self.read_offset + take]);
                self.read_offset += take;
                return Poll::Ready(Ok(()));
            }
            let mut bytes = [0; BUFFER_SIZE];
            let mut buffer = ReadBuf::new(&mut bytes);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buffer))?;
            if buffer.filled().is_empty() {
                if self.response.is_some() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to read response version",
                    )));
                }
                return Poll::Ready(self.decoder.finish());
            }
            let mut filled = buffer.filled();
            let header_rest;
            if let Some(header) = self.response.as_mut() {
                header.extend_from_slice(filled);
                if header[0] != 0 {
                    return Poll::Ready(Err(invalid("unexpected response version. Expecting 0")));
                }
                if header.len() < 2 || header.len() < 2 + header[1] as usize {
                    continue;
                }
                header_rest = header.split_off(2 + header[1] as usize);
                self.response = None;
                filled = &header_rest;
                if filled.is_empty() {
                    continue;
                }
            }
            let decoded = self.decoder.decode(filled)?;
            if decoded.direct {
                self.control.read_direct();
            }
            self.read_pending = decoded.data;
            self.read_offset = 0;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain_write(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = if self.response_left != 0 {
            let take = self.response_left.min(data.len());
            self.response_left -= take;
            self.write_pending = data[..take].to_vec();
            take
        } else {
            let take = MAX_CONTENT.min(data.len());
            let encoded = self.encoder.encode(&data[..take])?;
            self.write_pending = encoded.data;
            self.write_direct = encoded.direct;
            take
        };
        // Retain the encoded frame on Pending; no later call acknowledges this input again.
        if let Poll::Ready(result) = self.drain_write(cx) {
            result?;
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain_write(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: [u8; 16] = [42; 16];
    fn shared() -> SharedState {
        Arc::new(Mutex::new(State::new()))
    }
    fn frame(command: u8, content: &[u8], padding: usize, first: bool) -> Vec<u8> {
        let mut bytes = if first { UUID.to_vec() } else { Vec::new() };
        bytes.push(command);
        bytes.extend_from_slice(&(content.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(padding as u16).to_be_bytes());
        bytes.extend_from_slice(content);
        bytes.resize(bytes.len() + padding, 0);
        bytes
    }
    fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        let ext: &[u8] = if tls13 { &[0, 43, 0, 2, 3, 4] } else { &[] };
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(ext);
        let mut handshake = vec![2, 0, 0, body.len() as u8];
        handshake.extend(body);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }
    #[test]
    fn fragmented_uuid_headers_content_and_padding() {
        let mut bytes = frame(0, b"hello", 8, true);
        bytes.extend(frame(1, b"world", 3, false));
        bytes.extend_from_slice(b"plain");
        for size in 1..=bytes.len() {
            let mut decoder = Decoder::new(UUID, shared());
            let mut actual = Vec::new();
            for fragment in bytes.chunks(size) {
                let out = decoder.decode(fragment).unwrap();
                assert!(!out.direct);
                actual.extend(out.data);
            }
            assert_eq!(actual, b"helloworldplain");
            assert_eq!(decoder.decode(b"more").unwrap().data, b"more");
            decoder.finish().unwrap();
        }
    }
    #[test]
    fn invalid_uuid_command_and_truncated_frames() {
        let mut bytes = frame(0, b"hello", 0, true);
        bytes[0] ^= 1;
        assert!(Decoder::new(UUID, shared()).decode(&bytes).is_err());
        assert!(
            Decoder::new(UUID, shared())
                .decode(&frame(3, b"", 0, true))
                .is_err()
        );
        let mut decoder = Decoder::new(UUID, shared());
        decoder.decode(&frame(0, b"hello", 2, true)[..23]).unwrap();
        assert!(decoder.finish().is_err());
        let mut decoder = Decoder::new(UUID, shared());
        decoder.decode(&[42; 15]).unwrap();
        assert!(decoder.finish().is_err());
        let mut decoder = Decoder::new(UUID, shared());
        decoder.decode(&UUID).unwrap();
        assert!(decoder.finish().is_err());
    }
    #[test]
    fn direct_only_after_final_padding_and_empty_frames_work() {
        let bytes = frame(2, b"tls", 2, true);
        let mut decoder = Decoder::new(UUID, shared());
        let out = decoder.decode(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(out.data, b"tls");
        assert!(!out.direct);
        let out = decoder.decode(&bytes[bytes.len() - 1..]).unwrap();
        assert!(out.direct);
        assert!(out.data.is_empty());
        assert!(!decoder.decode(b"raw").unwrap().direct);
        let mut decoder = Decoder::new(UUID, shared());
        let mut bytes = frame(0, b"", 0, true);
        bytes.extend(frame(1, b"", 0, false));
        assert!(decoder.decode(&bytes).unwrap().data.is_empty());
        decoder.finish().unwrap();
    }
    #[test]
    fn bounded_encoding_uuid_once_and_plain_padding_end() {
        let mut encoder = Encoder::new(UUID, shared());
        let mut decoder = Decoder::new(UUID, shared());
        for index in 0..9 {
            let data = vec![b'x'; 20000];
            let out = encoder.encode(&data).unwrap();
            assert!(!out.direct);
            assert_eq!(decoder.decode(&out.data).unwrap().data, data);
            if index == 0 {
                assert_eq!(&out.data[..16], &UUID);
            }
        }
        assert!(!encoder.padding);
        assert_eq!(encoder.encode(b"plain").unwrap().data, b"plain");
    }
    #[test]
    fn tls_filter_checks_version_cipher_and_actual_extensions() {
        for cipher in [0x1301, 0x1302, 0x1303, 0x1304, 0x1305, 0xc02f] {
            for tls13 in [false, true] {
                let mut state = State::new();
                for byte in server_hello(cipher, tls13) {
                    state.observe_server(&[byte]);
                }
                assert!(state.is_tls12_or_above);
                assert_eq!(
                    state.enable_xtls,
                    tls13 && (0x1301..=0x1304).contains(&cipher)
                );
            }
        }
        let mut hello = server_hello(0x1301, false);
        hello[11..17].copy_from_slice(&[0, 43, 0, 2, 3, 4]);
        let mut state = State::new();
        state.observe_server(&hello);
        assert!(!state.enable_xtls);
    }
    #[test]
    fn tls13_transitions_at_complete_application_record_tls12_stays_tls() {
        for tls13 in [true, false] {
            let state = shared();
            let mut encoder = Encoder::new(UUID, state.clone());
            let mut decoder = Decoder::new(UUID, shared());
            let hello = server_hello(0x1301, tls13);
            let out = encoder.encode(&hello).unwrap();
            assert!(!out.direct);
            assert_eq!(decoder.decode(&out.data).unwrap().data, hello);
            let record = [23, 3, 3, 0, 4, 1, 2, 3, 4];
            for byte in &record[..record.len() - 1] {
                let out = encoder.encode(&[*byte]).unwrap();
                assert!(!out.direct);
                assert!(!decoder.decode(&out.data).unwrap().direct);
            }
            let out = encoder.encode(&record[record.len() - 1..]).unwrap();
            assert_eq!(out.direct, tls13);
            assert_eq!(decoder.decode(&out.data).unwrap().direct, tls13);
            assert!(!encoder.padding);
            assert_eq!(encoder.encode(b"raw").unwrap().data, b"raw");
        }
    }
    #[test]
    fn maximum_wire_lengths_stream_without_whole_frame_buffering() {
        let content = vec![7; u16::MAX as usize];
        let bytes = frame(1, &content, u16::MAX as usize, true);
        let mut decoder = Decoder::new(UUID, shared());
        let mut output = Vec::new();
        for chunk in bytes.chunks(257) {
            let decoded = decoder.decode(chunk).unwrap();
            assert!(decoded.data.len() <= chunk.len());
            output.extend(decoded.data);
        }
        assert_eq!(output, content);
        decoder.finish().unwrap();
    }
    #[tokio::test]
    async fn wrapper_preserves_response_header_and_flushes_partial_writes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (inner, mut peer) = tokio::io::duplex(17);
        let (mut wrapped, initial) =
            wrap(Box::new(inner), &[], UUID, DirectControl::default()).unwrap();
        assert!(initial.is_empty());
        let payload = vec![5; 20000];
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            wrapped.write_all(&[0]).await.unwrap();
            wrapped.write_all(&[0]).await.unwrap();
            wrapped.write_all(&payload).await.unwrap();
            wrapped.shutdown().await.unwrap();
        });
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        writer.await.unwrap();
        assert_eq!(&bytes[..2], &[0, 0]);
        assert_eq!(&bytes[2..18], &UUID);
        let mut decoder = Decoder::new(UUID, shared());
        assert_eq!(decoder.decode(&bytes[2..]).unwrap().data, expected);
        decoder.finish().unwrap();
    }
    #[tokio::test]
    async fn wrapper_decodes_initial_fragment_then_raw_transition() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (inner, mut peer) = tokio::io::duplex(17);
        let bytes = frame(2, b"payload", 31, true);
        let (mut wrapped, initial) = wrap(
            Box::new(inner),
            &bytes[..18],
            UUID,
            DirectControl::default(),
        )
        .unwrap();
        assert!(initial.is_empty());
        let writer = tokio::spawn(async move {
            for chunk in bytes[18..].chunks(3) {
                peer.write_all(chunk).await.unwrap();
            }
            peer.write_all(b"raw").await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let mut output = Vec::new();
        wrapped.read_to_end(&mut output).await.unwrap();
        writer.await.unwrap();
        assert_eq!(output, b"payloadraw");
    }
    #[tokio::test]
    async fn cancelled_pending_write_does_not_acknowledge_another_buffer() {
        use std::task::Waker;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (inner, mut peer) = tokio::io::duplex(1);
        let (mut wrapped, _) = wrap(Box::new(inner), &[], UUID, DirectControl::default()).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut wrapped).poll_write(&mut cx, &[0, 0]),
            Poll::Ready(Ok(2))
        ));
        assert!(
            Pin::new(&mut wrapped)
                .poll_write(&mut cx, b"cancelled")
                .is_pending()
        );
        let received = tokio::spawn(async move {
            let mut wire = Vec::new();
            peer.read_to_end(&mut wire).await.unwrap();
            assert_eq!(&wire[..2], &[0, 0]);
            let mut decoder = Decoder::new(UUID, shared());
            assert_eq!(decoder.decode(&wire[2..]).unwrap().data, b"x");
            decoder.finish().unwrap();
        });
        assert_eq!(wrapped.write(b"x").await.unwrap(), 1);
        wrapped.flush().await.unwrap();
        wrapped.shutdown().await.unwrap();
        received.await.unwrap();
    }
}
