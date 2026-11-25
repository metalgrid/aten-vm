//! ATEN virtual-media wire profile from runtime/vusb.pcap and libSharedLibrary64.so.
//! Capture: status probes (streams 0/3), HTTP-port probe (stream 1), and bulk-only
//! SCSI (stream 2). Unplug/keepalive are from Core_VM_SendUnMountPkt and
//! State_Fn_RX_PDU_TAG / FillKeepAlivePkt, not observed in this short capture.
use crate::Result;
use std::{io, io::SeekFrom, time::Duration};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::timeout,
};

const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// The BMC exchanges keepalives every few seconds on a healthy session and
/// serves no other traffic when a second client has taken the (global,
/// single-session) virtual-media slot. Silence therefore means preemption or
/// a dead peer; treat it as a disconnect so the caller can reconnect or exit.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_FRAME: usize = 128 * 1024;
const BLOCK: u64 = 2048;
const ENDPOINTS: &[u8] = &[6, 3, 1, 0x10, 2, 0x20, 3, 0x30];
const INQUIRY: &[u8] = b"\x05\x80\x00\x21\x1f\x00\x00\x00ATEN    Virtual CDROM   YS0J";

// GetConfig at 0x25e35..0x26d95, non-null-media branches; 19 descriptors.
const FEATURES: &[u8] = &[
    0x00, 0x00, 0x03, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x01, 0x03, 0x04,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x04,
    0x29, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x1d, 0x01, 0x00, 0x00, 0x1e, 0x05, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x04,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x03, 0x00, 0x04, 0x07, 0x00, 0x01, 0x00,
    0x01, 0x04, 0x03, 0x00, 0x01, 0x05, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01, 0x01, 0x07, 0xc0, 0x04, 0x08, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01,
];

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: [u8; 4],
    pub payload: Vec<u8>,
}

// State belongs to the reader, not the future, so selecting on read() cannot
// discard half a header/body. read_exact alone would not have this property.
#[derive(Default)]
struct FrameReader {
    header: [u8; 8],
    header_used: usize,
    payload: Vec<u8>,
    payload_used: usize,
}

impl FrameReader {
    async fn read<R: AsyncRead + Unpin>(&mut self, input: &mut R) -> Result<Frame> {
        while self.header_used < 8 {
            let n = input.read(&mut self.header[self.header_used..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "virtual-media connection closed during frame header",
                )
                .into());
            }
            self.header_used += n;
        }
        let len = u32::from_le_bytes(self.header[4..8].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(format!("virtual-media frame length {len} exceeds {MAX_FRAME}").into());
        }
        self.payload.resize(len, 0);
        while self.payload_used < len {
            let n = input.read(&mut self.payload[self.payload_used..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "virtual-media connection closed during frame body",
                )
                .into());
            }
            self.payload_used += n;
        }
        let frame = Frame {
            kind: self.header[..4].try_into().unwrap(),
            payload: std::mem::take(&mut self.payload),
        };
        self.header_used = 0;
        self.payload_used = 0;
        Ok(frame)
    }
}

/// Read one framed server PDU. Do not cancel this convenience function and then
/// reuse the stream; serve() uses a persistent, cancellation-safe reader instead.
pub async fn read_frame<R: AsyncRead + Unpin>(input: &mut R) -> Result<Frame> {
    FrameReader::default().read(input).await
}

async fn header<W: AsyncWrite + Unpin>(out: &mut W, kind: [u8; 4], len: u32) -> Result<()> {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&kind);
    bytes[4..].copy_from_slice(&len.to_le_bytes());
    out.write_all(&bytes).await?;
    Ok(())
}

async fn write_frame<W: AsyncWrite + Unpin>(out: &mut W, kind: [u8; 4], body: &[u8]) -> Result<()> {
    header(out, kind, u32::try_from(body.len())?).await?;
    out.write_all(body).await?;
    Ok(())
}

fn check_slot(slot: u8) -> Result<()> {
    if slot > 3 {
        return Err("slot must be in 0..=3 (and present in the server status reply)".into());
    }
    Ok(())
}

fn validate_status(frame: &Frame, slot: u8) -> Result<()> {
    check_slot(slot)?;
    if frame.kind != [0, 0, 0, 9]
        || frame.payload.is_empty()
        || frame.payload.len() != 1 + usize::from(frame.payload[0])
    {
        return Err("invalid virtual-media slot-status reply".into());
    }
    let count = frame.payload[0];
    if slot >= count {
        return Err(format!(
            "virtual-media slot {slot} does not exist; server reports {count} slots"
        )
        .into());
    }
    // Core_GetDevStatusFromFW, 0x19cd8: payload[slot + 1] == ff => free.
    if let Some(occupied) = frame.payload[1..].iter().position(|state| *state != 0xff) {
        return Err(format!(
            "virtual-media slot {occupied} is busy; refusing to mount while any media is active"
        )
        .into());
    }
    Ok(())
}

/// Use a separate short-lived TCP connection, exactly as capture streams 0/3.
/// Stream 1's 0a/0b exchange only discovers HTTP port 80 and is unnecessary here.
pub async fn probe(host: &str, port: u16, slot: u8) -> Result<()> {
    check_slot(slot)?;
    timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect((host, port)).await?;
        write_frame(&mut stream, [0, 0, 0, 8], &[]).await?;
        let frame = read_frame(&mut stream).await?;
        validate_status(&frame, slot)?;
        stream.shutdown().await?;
        Ok(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "virtual-media slot probe timed out",
        )
    })?
}

pub fn validate_auth(frame: &Frame) -> Result<()> {
    let raw = format!(
        "kind={:02x?} len={} body={:02x?}",
        frame.kind,
        frame.payload.len(),
        &frame.payload[..frame.payload.len().min(64)]
    );
    if frame.kind != [0, 0, 0, 2] || frame.payload.len() != 9 {
        return Err(
            format!("invalid virtual-media authentication/mount acknowledgement: {raw}").into(),
        );
    }
    // State_Fn_RX_MOUNT_DEV_STATUS: first payload byte is the result, not the
    // final byte. Status 0 succeeds; 1..6 dispatch distinct rejection messages.
    if frame.payload[0] != 0 {
        return Err(format!(
            "virtual-media authentication/mount rejected (status {}): {raw}",
            frame.payload[0]
        )
        .into());
    }
    Ok(())
}

pub async fn authenticate<S: AsyncRead + Unpin>(stream: &mut S) -> Result<()> {
    let frame = timeout(IO_TIMEOUT, read_frame(stream))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "virtual-media authentication timed out",
            )
        })??;
    validate_auth(&frame)
}

/// Authentication already sent the USB descriptors. This is the sole remaining
/// mount packet (pcap frame 38 / FillSetEPCMDPkt). No ISO length is sent here.
pub async fn mount<S: AsyncWrite + Unpin>(stream: &mut S, slot: u8) -> Result<()> {
    check_slot(slot)?;
    timeout(IO_TIMEOUT, write_frame(stream, [0, 0, 0, 7], ENDPOINTS))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "virtual-media endpoint setup timed out",
            )
        })?
}

/// Send Core_VM_SendUnMountPkt's exact unplug request, then half-close output.
/// Success means the request was flushed, NOT that remote slot release was
/// confirmed. Input may have a partially consumed CBW when serve was stopped,
/// so teardown deliberately does not parse it using a new frame reader.
/// Always discard this connection afterwards; a fresh probe can verify release.
pub async fn unmount<S: AsyncWrite + Unpin>(stream: &mut S, slot: u8) -> Result<()> {
    check_slot(slot)?;
    timeout(UNMOUNT_TIMEOUT, async {
        write_frame(stream, [0, 0, 0, 5], &[]).await?;
        stream.shutdown().await?;
        Ok(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "virtual-media unplug write timed out",
        )
    })?
}

struct Disc {
    blocks: u32,
    sense: [u8; 18],
    commands: u64,
    read_sectors: u64,
    read_commands: u64,
    op_counts: [u64; 256],
    min_lba: Option<u32>,
    max_lba_end: Option<u32>, // exclusive
}

impl Disc {
    fn new(size: u64) -> Result<Self> {
        if size == 0 || !size.is_multiple_of(BLOCK) || size / BLOCK > u64::from(u32::MAX) {
            return Err(
                "ISO size must be a nonzero multiple of 2048 bytes and fit READ CAPACITY(10)"
                    .into(),
            );
        }
        let mut sense = [0; 18];
        sense[0] = 0x70;
        sense[7] = 10;
        Ok(Self {
            blocks: (size / BLOCK) as u32,
            sense,
            commands: 0,
            read_sectors: 0,
            read_commands: 0,
            op_counts: [0; 256],
            min_lba: None,
            max_lba_end: None,
        })
    }

    async fn command<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        iso: &mut File,
        frame: Frame,
    ) -> Result<()> {
        let cbw = &frame.payload;
        if frame.kind[0..2] != [0x11, 2]
            || frame.kind[3] != 0
            || cbw.len() != 31
            || &cbw[..4] != b"USBC"
        {
            return Err("invalid ATEN USB command frame/CBW".into());
        }
        let expected = u32::from_le_bytes(cbw[8..12].try_into().unwrap());
        if !matches!(cbw[12], 0 | 0x80) || cbw[13] != 0 || !(1..=16).contains(&cbw[14]) {
            return Err("unsupported CBW flags, LUN, or command length".into());
        }
        if expected != 0 && cbw[12] != 0x80 {
            // No output-data transfer is safe for this read-only ISO profile.
            // Do not pretend the following data is another CBW/control packet.
            return Err("host requested a data-out transfer on the read-only ISO".into());
        }
        let cdb = &cbw[15..15 + usize::from(cbw[14])];
        self.commands += 1;
        self.op_counts[usize::from(cdb[0])] += 1;
        let min_len = match cdb[0] {
            0x25 | 0x28 | 0x46 | 0x5a => 10,
            _ => 6,
        };
        if cdb.len() < min_len {
            return Err("truncated SCSI command descriptor".into());
        }
        let mut data = Vec::new();
        let mut disk_read = None;
        let mut failed = false;
        let mut phase_error = false;
        match cdb[0] {
            0x00 | 0x1b | 0x1e => {
                // TEST UNIT READY / START STOP / PREVENT ALLOW
                phase_error = expected != 0;
            }
            0x03 => {
                // REQUEST SENSE; native ab_iso_ReqSense format
                data.extend_from_slice(&self.sense);
                data.truncate(usize::from(cdb[4]));
                self.sense[2] = 0;
                self.sense[12] = 0;
                self.sense[13] = 0;
            }
            0x12 if cdb[1] == 0 && cdb[2] == 0 => {
                data.extend_from_slice(INQUIRY);
                data.truncate(usize::from(cdb[4]));
            }
            0x25 if cdb[1..].iter().all(|b| *b == 0) => {
                data.extend_from_slice(&(self.blocks - 1).to_be_bytes());
                data.extend_from_slice(&(BLOCK as u32).to_be_bytes());
            }
            0x46 if cdb[1] <= 2 => {
                let start = u16::from_be_bytes([cdb[2], cdb[3]]);
                data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);
                let mut features = FEATURES;
                while !features.is_empty() {
                    let len = 4 + usize::from(features[3]);
                    if u16::from_be_bytes([features[0], features[1]]) >= start {
                        data.extend_from_slice(&features[..len]);
                    }
                    features = &features[len..];
                }
                let len = (data.len() - 4) as u32;
                data[..4].copy_from_slice(&len.to_be_bytes());
                // Native GetConfig ignores request-type bits and returns every
                // descriptor from starting feature onward; retain that behavior.
                data.truncate(usize::from(u16::from_be_bytes([cdb[7], cdb[8]])));
            }
            0x1a | 0x5a
                if cdb[3] == 0 && cdb[2] >> 6 != 3 && matches!(cdb[2] & 0x3f, 0 | 0x2a | 0x3f) =>
            {
                // Read-only standard MODE SENSE headers (not capture-verified).
                // Page 2a's values come from native pagecode_2ah at 0x2840f.
                let ten = cdb[0] == 0x5a;
                data.resize(if ten { 8 } else { 4 }, 0);
                data[if ten { 3 } else { 2 }] = 0x80; // write-protected
                if cdb[2] & 0x3f != 0 {
                    let mut page = [0u8; 30];
                    page[0] = 0x2a;
                    page[1] = 28;
                    if cdb[2] >> 6 != 1 {
                        // changeable-values mask is zero
                        for (i, value) in [
                            (2, 0x3f),
                            (4, 0x71),
                            (5, 0x77),
                            (6, 0x29),
                            (7, 0x23),
                            (8, 0x1b),
                            (9, 0x90),
                            (10, 1),
                            (13, 0xc6),
                            (14, 0x1b),
                            (15, 0x90),
                            (17, 0x10),
                            (23, 1),
                        ] {
                            page[i] = value;
                        }
                    }
                    data.extend_from_slice(&page);
                }
                let allocation = if ten {
                    let len = (data.len() - 2) as u16;
                    data[..2].copy_from_slice(&len.to_be_bytes());
                    usize::from(u16::from_be_bytes([cdb[7], cdb[8]]))
                } else {
                    data[0] = (data.len() - 1) as u8;
                    usize::from(cdb[4])
                };
                data.truncate(allocation);
            }
            0x28 => {
                let lba = u32::from_be_bytes(cdb[2..6].try_into().unwrap());
                let blocks = u32::from(u16::from_be_bytes([cdb[7], cdb[8]]));
                let bytes = blocks * BLOCK as u32;
                if u64::from(lba) + u64::from(blocks) > u64::from(self.blocks) {
                    self.sense[2] = 5;
                    self.sense[12] = 0x21; // LBA out of range
                    failed = true;
                } else if expected != bytes {
                    phase_error = true;
                } else {
                    self.read_commands += 1;
                    self.min_lba = Some(self.min_lba.map_or(lba, |m| m.min(lba)));
                    let end = lba + blocks;
                    self.max_lba_end = Some(self.max_lba_end.map_or(end, |m| m.max(end)));
                    disk_read = Some((u64::from(lba) * BLOCK, bytes));
                }
            }
            _ => {
                self.sense[2] = 5;
                self.sense[12] = 0x24; // native invalid-CDB sense
                failed = true;
            }
        }
        let mut sent = 0u32;
        let endpoint = frame.kind[2]; // State_Fn_RX_PDU_TAG / FillDataPDUTag
        if let Some((offset, bytes)) = disk_read {
            if bytes != 0 {
                iso.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(|e| format!("ISO seek failed at byte {offset}: {e}"))?;
                // One PDU per command, streamed in bounded chunks. Neither TCP
                // segmentation nor our disk buffer size changes the PDU length.
                header(stream, [0x22, 0, endpoint, 0], bytes).await?;
                let mut buffer = [0; 64 * 1024];
                while sent < bytes {
                    let n = ((bytes - sent) as usize).min(buffer.len());
                    iso.read_exact(&mut buffer[..n]).await.map_err(|e| {
                        format!("ISO read failed at byte {}: {e}", offset + u64::from(sent))
                    })?;
                    stream.write_all(&buffer[..n]).await?;
                    sent += n as u32;
                }
            }
        } else if !data.is_empty() && !failed && !phase_error {
            data.truncate(expected as usize);
            if !data.is_empty() {
                write_frame(stream, [0x22, 0, endpoint, 0], &data).await?;
                sent = data.len() as u32;
            }
        }
        let mut csw = [0; 13];
        csw[..4].copy_from_slice(b"USBS");
        csw[4..8].copy_from_slice(&cbw[4..8]);
        csw[8..12].copy_from_slice(&(expected - sent).to_le_bytes());
        csw[12] = if phase_error { 2 } else { u8::from(failed) };
        write_frame(stream, [0x22, 0, endpoint, 0xff], &csw).await?;
        if disk_read.is_some() {
            self.read_sectors += u64::from(sent) / BLOCK;
        }
        Ok(())
    }
}

/// Serve ISO sectors on demand. Signal the watch channel instead of cancelling
/// this future. Writes finish (with a timeout) before shutdown returns Ok; main
/// then calls unmount(). On an error discard the connection without sending
/// control into a potentially partial response PDU.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    iso: &mut File,
    size: u64,
    slot: u8,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    check_slot(slot)?;
    let mut disc = Disc::new(size)?;
    let started = std::time::Instant::now();
    let mut stats_tick = tokio::time::interval(std::time::Duration::from_secs(10));
    stats_tick.tick().await; // first tick completes immediately
    let mut reader = FrameReader::default();
    loop {
        if *shutdown.borrow() {
            break;
        }
        let frame = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
                continue;
            },
            _ = stats_tick.tick() => {
                eprintln!("{}", stats_line(&disc, started.elapsed()));
                continue;
            },
            frame = timeout(IDLE_TIMEOUT, reader.read(stream)) => match frame {
                Ok(Ok(frame)) => frame,
                Ok(Err(e)) => {
                    if disc.commands == 0 {
                        return Err(format!(
                            "mount not confirmed (no valid USBC command received): {e}; partial header={:02x?}",
                            &reader.header[..reader.header_used]).into());
                    }
                    return Err(e);
                }
                Err(_) => return Err(Box::new(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "no frames from BMC for 30s (session preempted by another client, or peer dead)",
                ))),
            },
        };
        match frame.kind {
            [0, 0, 0, 6] if frame.payload.is_empty() => break,
            [0, 0, 0, 4] => {
                timeout(IO_TIMEOUT, write_frame(stream, [0, 0, 0, 3], &[0xff; 4]))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "virtual-media keepalive write timed out",
                        )
                    })??;
            }
            [0x11, 2, _, 0] => {
                timeout(IO_TIMEOUT, disc.command(stream, iso, frame))
                    .await
                    // This deadline also covers ISO access, so an elapsed
                    // deadline cannot safely be classified as a network drop.
                    .map_err(|_| "virtual-media SCSI response timed out (ISO or transport); discard connection")??;
            }
            _ => return Err(format!("unsupported virtual-media PDU {:02x?}", frame.kind).into()),
        }
    }
    eprintln!(
        "[vm done] slot {slot}, ISO {size} B ({} sectors)",
        size / BLOCK
    );
    eprintln!("{}", stats_line(&disc, started.elapsed()));
    Ok(())
}

fn hhmmss(secs: u64) -> String {
    let (h, rem) = (secs / 3600, secs % 3600);
    format!("{h:02}:{:02}:{:02}", rem / 60, rem % 60)
}

/// One-line session statistics: command mix, ISO traffic, throughput, LBA range.
fn stats_line(disc: &Disc, elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs().max(1);
    let mibs = f64::from(u32::try_from(disc.read_sectors).unwrap_or(u32::MAX)) * (BLOCK as f64)
        / (1024.0 * 1024.0)
        / secs as f64;
    let known: [(u8, &str); 10] = [
        (0x00, "TUR"),
        (0x03, "SENSE"),
        (0x12, "INQ"),
        (0x1a, "MODE6"),
        (0x1b, "START_STOP"),
        (0x1e, "PREVENT"),
        (0x25, "RD_CAP"),
        (0x28, "RD10"),
        (0x46, "GET_CFG"),
        (0x5a, "MODE10"),
    ];
    let mut ops: Vec<String> = known
        .iter()
        .filter_map(|(op, name)| {
            let c = disc.op_counts[usize::from(*op)];
            (c > 0).then(|| format!("{name}={c}"))
        })
        .collect();
    let other: u64 = disc
        .op_counts
        .iter()
        .enumerate()
        .filter(|(i, _)| !known.iter().any(|(op, _)| usize::from(*op) == *i))
        .map(|(_, c)| c)
        .sum();
    if other > 0 {
        ops.push(format!("other={other}"));
    }
    let lba = match (disc.min_lba, disc.max_lba_end) {
        (Some(a), Some(b)) => format!(", LBA {a}..{}", b.saturating_sub(1)),
        _ => String::new(),
    };
    format!(
        "[vm {}] cmds={}, reads={} sectors ({} B, {mibs:.2} MiB/s){}, ops: {}",
        hhmmss(secs),
        disc.commands,
        disc.read_sectors,
        disc.read_sectors * BLOCK,
        lba,
        ops.join(",")
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn decode(raw: &[u8]) -> Frame {
        let len = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
        assert_eq!(len + 8, raw.len());
        Frame {
            kind: raw[..4].try_into().unwrap(),
            payload: raw[8..].to_vec(),
        }
    }

    struct Iso(PathBuf);
    impl Iso {
        async fn new(size: u64) -> (Self, File) {
            let path = std::env::temp_dir().join(format!(
                "aten-vm-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let f = std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.set_len(size).unwrap();
            (Self(path), File::from_std(f))
        }
    }
    impl Drop for Iso {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn cbw(cdb: &[u8], len: u32) -> Frame {
        let mut payload = vec![0; 31];
        payload[..4].copy_from_slice(b"USBC");
        payload[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        payload[8..12].copy_from_slice(&len.to_le_bytes());
        payload[12] = if len == 0 { 0 } else { 0x80 };
        payload[14] = cdb.len() as u8;
        payload[15..15 + cdb.len()].copy_from_slice(cdb);
        Frame {
            kind: [0x11, 2, 1, 0],
            payload,
        }
    }

    #[test]
    fn captured_status_and_auth_reject_busy_and_failure() {
        let status = decode(&hex("000000090400000003ffffff"));
        for slot in 0..3 {
            validate_status(&status, slot).unwrap();
        }
        assert!(validate_status(&status, 3).is_err());
        let mut busy = status;
        for value in [0, 1, 3, 0xfe] {
            busy.payload[2] = value;
            assert!(
                validate_status(&busy, 0)
                    .unwrap_err()
                    .to_string()
                    .contains("slot 1 is busy")
            );
        }
        let mut ack = decode(&hex("0000000209000000000000000000000000"));
        validate_auth(&ack).unwrap();
        for code in 1..=6 {
            ack.payload[0] = code;
            assert!(
                validate_auth(&ack)
                    .unwrap_err()
                    .to_string()
                    .contains("body=")
            );
        }
        ack.payload.clear();
        assert!(validate_auth(&ack).is_err());
        for size in [0, 1, 2049, (u64::from(u32::MAX) + 1) * BLOCK] {
            assert!(Disc::new(size).is_err());
        }
    }

    #[tokio::test]
    async fn fragmented_coalesced_truncated_and_oversized_frames() {
        let first = hex("0000000209000000000000000000000000");
        let second = hex("000000090400000003ffffff");
        let mut both = first.clone();
        both.extend(&second);
        let (mut tx, mut rx) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            tx.write_all(&both).await.unwrap();
        });
        assert_eq!(read_frame(&mut rx).await.unwrap(), decode(&first));
        assert_eq!(read_frame(&mut rx).await.unwrap(), decode(&second));
        writer.await.unwrap();
        assert!(
            read_frame(&mut rx)
                .await
                .unwrap_err()
                .downcast_ref::<io::Error>()
                .is_some()
        );
        let mut input = first[..10].as_ref();
        assert!(read_frame(&mut input).await.is_err());
        let mut input = [0, 0, 0, 2, 0xff, 0xff, 0xff, 0x7f].as_ref();
        assert!(
            read_frame(&mut input)
                .await
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        let mut joined = first.clone();
        joined.extend(&second);
        let mut input = joined.as_slice();
        assert_eq!(read_frame(&mut input).await.unwrap(), decode(&first));
        assert_eq!(read_frame(&mut input).await.unwrap(), decode(&second));
    }

    #[tokio::test]
    async fn persistent_reader_survives_cancelled_partial_header_and_body() {
        let raw = hex("0000000209000000000000000000000000");
        for split in [3, 10] {
            let (mut tx, mut rx) = tokio::io::duplex(64);
            let mut reader = FrameReader::default();
            tx.write_all(&raw[..split]).await.unwrap();
            assert!(
                timeout(Duration::from_millis(5), reader.read(&mut rx))
                    .await
                    .is_err()
            );
            tx.write_all(&raw[split..]).await.unwrap();
            assert_eq!(reader.read(&mut rx).await.unwrap(), decode(&raw));
        }
    }

    #[tokio::test]
    async fn replay_every_captured_scsi_exchange_byte_for_byte() {
        let frames: Vec<(char, Vec<u8>)> = include_str!("../tests/fixtures/vusb-stream2.txt")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| (line.chars().next().unwrap(), hex(&line[2..])))
            .collect();
        let size = 0x2c200 * BLOCK;
        let (_guard, mut iso) = Iso::new(size).await;
        let mut offset = None;
        for (direction, raw) in &frames {
            let f = decode(raw);
            if *direction == 'S' && f.payload.starts_with(b"USBC") && f.payload[15] == 0x28 {
                offset = Some(
                    u64::from(u32::from_be_bytes(f.payload[17..21].try_into().unwrap())) * BLOCK,
                );
            }
            if *direction == 'C'
                && f.kind == [0x22, 0, 1, 0]
                && let Some(off) = offset.take()
            {
                iso.seek(SeekFrom::Start(off)).await.unwrap();
                iso.write_all(&f.payload).await.unwrap();
            }
        }
        iso.flush().await.unwrap();
        let (mut server, mut client) = tokio::io::duplex(113);
        let (stop, mut shutdown) = watch::channel(false);
        let client_task = async {
            authenticate(&mut client).await.unwrap();
            mount(&mut client, 0).await.unwrap();
            serve(&mut client, &mut iso, size, 0, &mut shutdown)
                .await
                .unwrap();
            unmount(&mut client, 0).await.unwrap();
        };
        let server_task = async {
            for (direction, raw) in frames {
                if direction == 'S' {
                    for chunk in raw.chunks(3) {
                        server.write_all(chunk).await.unwrap();
                    }
                } else {
                    let mut actual = vec![0; raw.len()];
                    server.read_exact(&mut actual).await.unwrap();
                    assert_eq!(actual, raw);
                }
            }
            stop.send(true).unwrap();
            assert_eq!(
                read_frame(&mut server).await.unwrap(),
                decode(&hex("0000000500000000"))
            );
        };
        timeout(Duration::from_secs(5), async {
            tokio::join!(client_task, server_task);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scsi_bounds_sense_residue_modes_and_native_features() {
        let (_guard, mut iso) = Iso::new(2 * BLOCK).await;
        let mut disc = Disc::new(2 * BLOCK).unwrap();
        let mut output = Vec::new();
        disc.command(
            &mut output,
            &mut iso,
            cbw(&[0x28, 0, 0, 0, 0, 2, 0, 0, 1, 0], 2048),
        )
        .await
        .unwrap();
        let csw = decode(&output);
        assert_eq!(csw.payload[12], 1);
        assert_eq!(&csw.payload[8..12], &2048u32.to_le_bytes());
        output.clear();
        disc.command(&mut output, &mut iso, cbw(&[3, 0, 0, 0, 18, 0], 18))
            .await
            .unwrap();
        let mut input = output.as_slice();
        let sense = read_frame(&mut input).await.unwrap();
        assert_eq!((sense.payload[2], sense.payload[12]), (5, 0x21));
        assert_eq!(disc.sense[2], 0);
        output.clear();
        disc.command(
            &mut output,
            &mut iso,
            cbw(&[0x46, 0, 0, 0, 0, 0, 0, 0, 0xff, 0], 255),
        )
        .await
        .unwrap();
        let mut input = output.as_slice();
        let config = read_frame(&mut input).await.unwrap();
        assert_eq!(&config.payload[..8], &[0, 0, 0, 0x98, 0, 0, 0, 8]);
        assert_eq!(config.payload.len(), 156);
        assert_eq!(read_frame(&mut input).await.unwrap().payload[8], 99);
        for (cdb, n, wp, page) in [
            (vec![0x1a, 8, 0x3f, 0, 0xff, 0], 34, 2, 4),
            (vec![0x5a, 8, 0x2a, 0, 0, 0, 0, 0, 0xff, 0], 38, 3, 8),
        ] {
            output.clear();
            disc.command(&mut output, &mut iso, cbw(&cdb, 255))
                .await
                .unwrap();
            let mut input = output.as_slice();
            let mode = read_frame(&mut input).await.unwrap();
            assert_eq!(mode.payload.len(), n);
            assert_eq!(mode.payload[wp], 0x80);
            assert_eq!(&mode.payload[page..page + 2], &[0x2a, 28]);
        }
        output.clear();
        disc.command(
            &mut output,
            &mut iso,
            cbw(&[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0], 512),
        )
        .await
        .unwrap();
        assert_eq!(decode(&output).payload[12], 2);
        output.clear();
        disc.command(&mut output, &mut iso, cbw(&[0xff, 0, 0, 0, 0, 0], 0))
            .await
            .unwrap();
        assert_eq!(decode(&output).payload[12], 1);
        output.clear();
        iso.set_len(0).await.unwrap();
        let error = disc
            .command(
                &mut output,
                &mut iso,
                cbw(&[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0], 2048),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ISO read failed"));
        assert!(error.downcast_ref::<io::Error>().is_none());
    }

    #[tokio::test]
    async fn shutdown_finishes_partial_outbound_data_before_unplug() {
        let (_guard, mut iso) = Iso::new(BLOCK).await;
        let (mut server, mut client) = tokio::io::duplex(1);
        let (stop, mut shutdown) = watch::channel(false);
        let peer = async {
            let request = cbw(&[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0], 2048);
            write_frame(&mut server, request.kind, &request.payload)
                .await
                .unwrap();
            // Let a response start, then notify while the one-byte stream is full.
            let first = server.read_u8().await.unwrap();
            assert_eq!(first, 0x22);
            stop.send(true).unwrap();
            let mut rest = vec![0; 8 + 2048 - 1];
            server.read_exact(&mut rest).await.unwrap();
            assert_eq!(read_frame(&mut server).await.unwrap().payload[12], 0);
            assert_eq!(read_frame(&mut server).await.unwrap().kind, [0, 0, 0, 5]);
        };
        let service = async {
            serve(&mut client, &mut iso, BLOCK, 0, &mut shutdown)
                .await
                .unwrap();
            unmount(&mut client, 0).await.unwrap();
        };
        timeout(Duration::from_secs(5), async {
            tokio::join!(peer, service);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn multiblock_reads_keep_one_pdu_and_controls_match_native_bytes() {
        let size = 70 * BLOCK;
        let (_guard, mut iso) = Iso::new(size).await;
        let mut disc = Disc::new(size).unwrap();
        let mut output = Vec::new();
        disc.command(
            &mut output,
            &mut iso,
            cbw(&[0x28, 0, 0, 0, 0, 1, 0, 0, 69, 0], 69 * 2048),
        )
        .await
        .unwrap();
        assert_eq!(
            u32::from_le_bytes(output[4..8].try_into().unwrap()),
            69 * 2048
        );
        let offset = 8 + 69 * 2048;
        assert_eq!(decode(&output[offset..]).payload[12], 0);
        assert_eq!(disc.read_sectors, 69);
        let (mut server, mut client) = tokio::io::duplex(64);
        let (_stop, mut shutdown) = watch::channel(false);
        let peer = async {
            write_frame(&mut server, [0, 0, 0, 4], &[]).await.unwrap();
            assert_eq!(
                read_frame(&mut server).await.unwrap(),
                decode(&hex("0000000304000000ffffffff"))
            );
            write_frame(&mut server, [0, 0, 0, 6], &[]).await.unwrap();
        };
        let service = serve(&mut client, &mut iso, size, 0, &mut shutdown);
        let (_, result) = tokio::join!(peer, service);
        result.unwrap();
    }

    #[tokio::test]
    async fn disconnect_before_first_command_is_not_retryable_but_established_drop_is() {
        let (_guard, mut iso) = Iso::new(BLOCK).await;
        let (_stop, mut shutdown) = watch::channel(false);
        for established in [false, true] {
            let (mut server, mut client) = tokio::io::duplex(256);
            let peer = async {
                if established {
                    let request = cbw(&[0, 0, 0, 0, 0, 0], 0);
                    write_frame(&mut server, request.kind, &request.payload)
                        .await
                        .unwrap();
                    read_frame(&mut server).await.unwrap();
                }
                server.shutdown().await.unwrap();
            };
            let service = serve(&mut client, &mut iso, BLOCK, 0, &mut shutdown);
            let (_, result) = tokio::join!(peer, service);
            let err = result.unwrap_err();
            assert_eq!(err.downcast_ref::<io::Error>().is_some(), established);
            if !established {
                assert!(err.to_string().contains("mount not confirmed"));
            }
        }
    }
}

#[cfg(test)]
mod stats_tests {
    use super::*;

    fn sample_disc() -> Disc {
        let mut d = Disc::new(2048 * 4).unwrap();
        d.commands = 7;
        d.read_sectors = 5;
        d.read_commands = 2;
        d.op_counts[0x00] = 2;
        d.op_counts[0x12] = 1;
        d.op_counts[0x25] = 1;
        d.op_counts[0x28] = 2;
        d.op_counts[0x99] = 1;
        d.min_lba = Some(2);
        d.max_lba_end = Some(4);
        d
    }

    #[test]
    fn stats_line_shows_mix_traffic_range() {
        let line = stats_line(&sample_disc(), std::time::Duration::from_secs(30));
        for needle in [
            "[vm 00:00:30]",
            "cmds=7",
            "reads=5 sectors (10240 B",
            "LBA 2..3",
            "TUR=2",
            "RD10=2",
            "other=1",
        ] {
            assert!(line.contains(needle), "missing `{needle}` in: {line}");
        }
    }

    #[test]
    fn stats_line_without_reads_has_no_lba() {
        let d = Disc::new(2048).unwrap();
        let line = stats_line(&d, std::time::Duration::from_secs(5));
        assert!(!line.contains("LBA"));
        assert!(line.contains("cmds=0"));
    }
}
