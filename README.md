# aten-vm

A small Rust client for the legacy ATEN/Supermicro vUSB protocol. It serves a
**local, read-only ISO** as a virtual CD-ROM; it does not open a KVM session,
upload an image to the BMC, or implement any power/reset operations.

## Download a release

Static linux/amd64 binaries are attached to every
[GitHub release](https://github.com/metalgrid/aten-vm/releases) tagged `v*`:
`aten-vm-<tag>-linux-amd64.tar.gz` plus a matching `.sha256` file. The binary
is statically linked and needs no runtime libraries. CI builds each release
from its tagged commit. The checksum comes from the same CI run; it detects
transfer corruption, not tampering.

```sh
tag=v0.1.1
curl -LO "https://github.com/metalgrid/aten-vm/releases/download/${tag}/aten-vm-${tag}-linux-amd64.tar.gz"
curl -LO "https://github.com/metalgrid/aten-vm/releases/download/${tag}/aten-vm-${tag}-linux-amd64.tar.gz.sha256"
sha256sum -c "aten-vm-${tag}-linux-amd64.tar.gz.sha256"
tar xzf "aten-vm-${tag}-linux-amd64.tar.gz"
```

## Build from source

You need Rust 1.85 or newer (the crate uses edition 2024) and a C compiler
for linking. TLS uses rustls; there is no OpenSSL dependency.

```sh
cargo build --release    # binary: target/release/aten-vm
cargo test
```

For a static binary like the released artifact:

```sh
rustup target add x86_64-unknown-linux-musl   # also install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

## Run

```sh
./aten-vm --host 172.31.224.254 \
  --user ADMIN --pass 'YOUR_PASSWORD' --iso /path/to/image.iso
```

Or use the two **literal** JNLP arguments 1 and 2, without base64-decoding them:

```sh
./aten-vm --host 172.31.224.254 \
  --token-pair 'USER_TOKEN' 'PASS_TOKEN' --iso /path/to/image.iso
```

Optional `--slot N` selects a zero-based slot 0–2 (default 0).
`--port N` overrides the JNLP vUSB port; token-pair mode defaults to port 623.
Use Ctrl-C to detach and exit. Keep the program running while the target
machine uses the disc. The ISO must be a nonempty regular file whose size is
a multiple of 2048 bytes. Do not modify or replace its contents while serving.

The program checks slot occupancy before sending authentication/mount data.
It conservatively refuses to mount if **any** slot is occupied, even when the
requested slot is free. It never takes over an existing mount.
Authentication and mount errors are fatal: no password retries, token
re-minting, slot switching, or protocol-variation attempts. After an established
session's TCP connection drops, it reconnects using **the same tokens** and
checks slot occupancy again. If the old session still appears occupied, it
stops rather than forcefully clearing it.

## Security

This is a compatibility tool for obsolete firmware on a trusted management
network, **not a secure virtual-media protocol**:

* HTTPS certificate verification is deliberately disabled for the BMC's
  self-signed certificate. Redirects are not followed.
* vUSB uses a fixed, public RC4 key and is not TLS-encrypted.
* Passwords and tokens supplied on the command line can appear in shell
  history and process listings. Do not use this across an untrusted network.
* Active tokens and web SID cookies are not deliberately logged.

## Source map and evidence

* `src/mint.rs`: one login POST and one JNLP GET; validates the SID cookie,
  XML-decodes argument text, and preserves literal token bytes. A small
  `quick-xml` dependency handles XML entities rather than inventing a parser.
* `src/auth.rs`: hand-written RC4; exact 44-byte fixed authentication body
  and eight USB descriptor records. The clear length field excludes the
  appended descriptors. Tests reconstruct all 226 bytes of capture frame 33.
* `src/proto.rs`: bounded TCP frame parsing, occupancy probes,
  endpoint mapping, SCSI responses and on-demand ISO sector reads. See
  `PROTOCOL-API.md` for wire evidence and integration details.
* `src/main.rs`: CLI validation, lifecycle, same-token reconnect and Ctrl-C.

The local references are `../inspection/vusb-auth.md`,
`../inspection/vusb_auth_ref.py`, `../inspection/libSharedLibrary64.so`,
and `../runtime/vusb.pcap`. No Java/native viewer code is executed.

The capture's command-7 message advertises endpoint mappings, **not ISO size**.
Size is communicated in SCSI READ CAPACITY responses. TCP segment boundaries
are not message boundaries: responses may combine data and status, and large
data transfers may span several TCP packets.

## Compatibility limits

* Targets the supplied 2019 ATEN/Supermicro firmware and captured USB profile;
  this is not a generic IPMI/Redfish virtual-media implementation.
* Linux is currently required for the four-byte nonce read from
  `/dev/urandom`. It retains the native nonnegative 31-bit field range but
  does not reproduce libc `srand/rand` seed selection.
* ISO data is streamed from disk; READ(10) addressing limits apply.
* Implements TEST UNIT READY, REQUEST SENSE, INQUIRY, READ CAPACITY(10),
  READ(10), GET CONFIGURATION, MODE SENSE(6/10), START STOP UNIT, and
  PREVENT/ALLOW MEDIUM REMOVAL. Unsupported SCSI commands return CHECK
  CONDITION; READ TOC, READ(12), and GET EVENT STATUS are not implemented.
  This is not a complete MMC implementation. MODE SENSE is
  standard read-only framing with the native capabilities page, not verified
  by the supplied capture.
* Unplug (`0000000500000000`) and keepalive behavior come from native-library
  disassembly: the supplied short capture contains no unplug. Ctrl-C finishes
  any current response before sending unplug. Successful transmission alone
  does not confirm remote slot release.
* Commands are processed serially in captured USB bulk-only ordering, retaining
  each request's tag. This is not USB Attached SCSI tagged queueing.
* An occupied slot, unknown protocol control message, authentication rejection,
  or expired token stops the program. Start a new invocation to explicitly mint
  fresh tokens.
* The BMC allows exactly **one virtual-media session globally**: a second
  `aten-vm` (or Java viewer) mount takes the session over, and the BMC silently
  abandons the first connection without a FIN. `serve` detects 30s of frame
  silence, classifies it as a disconnect, and the first instance then exits
  through the normal reconnect/probe path (it will report the slot as busy).
* The mount ends with the TCP session. A reconnect can cause a guest-visible
  media detach/reattach and cannot guarantee uninterrupted boot.

## Verification

Checked with Rust 1.100.0 and Cargo 1.100.0; release CI runs the same checks:

```text
cargo fmt --check                         PASS
cargo test                               22 passed; 0 failed
cargo clippy --all-targets -- -D warnings PASS
cargo build --release                    Finished release profile [optimized]
```

The offline replay test checks **88 captured PDUs / 34 SCSI commands / 15
sector reads** byte-for-byte. Other tests cover RC4, the complete auth vector,
split/coalesced/oversized frames, occupied slots, invalid acknowledgements,
read bounds, sense/residue, multi-chunk reads, and shutdown during a response.

**Live verification was blocked at web login.** One invocation targeted
`172.31.224.254` with the supplied credentials and
`/home/iso/Downloads/netboot.xyz-legacy.iso`. It exited after 1.5 seconds:

```text
web login rejected: SID cleared/invalid (bad credentials or session rejection); not retrying
```

The diagnostic does not distinguish a cleared cookie from a nonconforming SID;
the original cookie was not retained/logged. **Only one login attempt was made,
with no retry. No JNLP fetch, vUSB authentication, mount, SCSI traffic,
unmount, power action, or KVM session followed.** See `LIVE-TEST.txt`.

Therefore live mounting, nonce acceptance, real-device reconnect, remote
unmount confirmation, and ISO bootability remain **unverified**. A future live
attempt needs explicitly renewed authorization and valid web credentials or
fresh manually obtained tokens; do not interpret passing offline tests as a
successful BMC mount.
