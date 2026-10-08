# Secure Inline Communication Prototype (Linux / C++17)

This repository is a **buildable cryptographic prototype and NFQUEUE integration scaffold** for:

`PC1 -> Device1 -> Device2 -> PC2`

It implements:
- X25519 ephemeral key agreement authenticated by provisioned Ed25519 device signing keys
- HKDF-SHA-256 directional AES-256-GCM keys and nonce prefixes
- AES-256-GCM payload encryption/decryption
- monotonically increasing per-direction record counters and receiver replay rejection
- a small crypto self-test executable
- an NFQUEUE interception scaffold showing where selected IPv4/TCP packets are classified

## Important protocol limitation

This is not a drop-in transparent TCP encryption appliance. The requirements “encrypt only the TCP payload”, “append a 16-byte GCM tag”, “preserve the original IP/TCP headers”, “no custom protocol header”, and “use a unique nonce for every encrypted packet” are not jointly implementable as a general-purpose TCP proxy without additional coordination.

Reasons:
1. Appending a 16-byte tag changes the TCP sequence-space length. If the sender and receiver TCP endpoints are unchanged, ACKs, retransmissions, SACK blocks, and sequence numbers must be translated bidirectionally.
2. A receiver needs to know the nonce/counter for each packet. With no nonce/counter field, it must be derived from external synchronized state or conveyed over a separate authenticated control channel.
3. TCP is a byte stream, not a packet-record protocol. Segment boundaries can change due to MSS, retransmission, coalescing, offload, and resegmentation. A proxy cannot rely on original packet boundaries surviving a TCP connection.
4. A retransmission must resend the cached ciphertext/tag for the same stream range, not encrypt it again with a new nonce or reuse a nonce for different plaintext.

Therefore, the safest practical architecture is a TCP-aware proxy: Device1 terminates the PC1 TCP connection, then sends protected application records to Device2 over a dedicated device-to-device transport with explicit authenticated framing (or a separate control channel that reliably maps record lengths/counters). Device2 decrypts and opens a separate TCP connection to PC2. This preserves application bytes and selected-flow semantics, **not the original end-to-end TCP headers or connection**.

The crypto module below intentionally uses an explicit counter in its in-memory record API so nonce uniqueness and replay protection are testable. Do not deploy the NFQUEUE scaffold as a security gateway until the framing, proxy state machine, routing, failure behavior, and integration tests are completed.

## Dependencies (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev libnetfilter-queue-dev
```

## Build and test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/crypto_demo
```

The demo creates ephemeral X25519 keys, authenticates the handshake transcript using provisioned Ed25519 signing keys, derives directional keys, encrypts/decrypts a message, and rejects replay.

## Provisioned identities

For a real deployment, each device must have the other device's Ed25519 public key pinned in a trusted configuration. The demo generates keys at runtime only to make the test self-contained. Replace that test key generation with a secure provisioning process, private-key file permissions (or a TPM/HSM), rotation, and revocation.

## NFQUEUE scaffold

`src/nfqueue_scaffold.cpp` receives IPv4 packets through NFQUEUE and classifies TCP traffic. It currently accepts packets unchanged; it does not rewrite them or pretend to implement a complete tunnel. Configure queue rules only in an isolated lab.

Example (lab only; adapt interface/ports and ensure you have an out-of-band recovery path):

```bash
sudo iptables -I FORWARD 1 -p tcp --dport 8443 -j NFQUEUE --queue-num 42
sudo ./build/nfqueue_scaffold 42
```

Remove the test rule afterward:

```bash
sudo iptables -D FORWARD -p tcp --dport 8443 -j NFQUEUE --queue-num 42
```

This example uses the legacy `iptables` NFQUEUE target. Equivalent `nftables` queue rules are possible. The process needs root or suitable `CAP_NET_ADMIN` privileges.

## Suggested production architecture

- PC1 -> Device1 local TCP listener (original flow terminates here)
- Device1 -> Device2 dedicated protected transport, authenticated by the handshake
- Device2 -> PC2 outbound TCP connection
- separate reverse-direction state/keys/counters
- record framing with length + counter authenticated as AAD, or a reliable authenticated control channel that binds each record to a counter
- bounded buffers, timeouts, connection mapping, half-close, cancellation, backpressure
- explicit policy for MTU/MSS, congestion control, and fail-closed behavior

If the no-custom-header constraint is absolute, do not use a generic TCP stream as a packet-record tunnel and do not claim arbitrary TCP transparency. A narrowly scoped packet-level design requires a rigorously specified mapping for nonce, session, and original packet length, plus full bidirectional TCP sequence/ACK/SACK translation and retransmission caching.
