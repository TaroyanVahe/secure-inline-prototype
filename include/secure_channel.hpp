#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace sic {

using Bytes = std::vector<std::uint8_t>;
using Key32 = std::array<std::uint8_t, 32>;
using NoncePrefix4 = std::array<std::uint8_t, 4>;
using Tag16 = std::array<std::uint8_t, 16>;

struct Identity {
    Key32 ed25519_private{};
    Key32 ed25519_public{};
};

struct EphemeralX25519 {
    Key32 private_key{};
    Key32 public_key{};
};

struct DirectionKeys {
    Key32 aes_key{};
    NoncePrefix4 nonce_prefix{};
};

struct SessionKeys {
    DirectionKeys device1_to_device2;
    DirectionKeys device2_to_device1;
};

struct Record {
    std::uint64_t counter{};
    Bytes ciphertext;
    Tag16 tag{};
};

Identity generate_ed25519_identity();
EphemeralX25519 generate_x25519_keypair();
Key32 ed25519_public_from_private(const Key32& private_key);
Key32 x25519_public_from_private(const Key32& private_key);

// Signature over the complete transcript: role label, both ephemeral public keys,
// and both provisioned identity public keys. The peer identity key must be pinned.
Bytes sign_transcript(const Key32& ed25519_private, const Bytes& transcript);
bool verify_transcript(const Key32& ed25519_public, const Bytes& transcript,
                       const Bytes& signature);

SessionKeys derive_session_keys(
    const Key32& local_ephemeral_private,
    const Key32& peer_ephemeral_public,
    const Bytes& transcript_context);

class Sender {
public:
    explicit Sender(DirectionKeys keys);
    Record encrypt(const Bytes& plaintext, const Bytes& aad = {});
private:
    DirectionKeys keys_;
    std::uint64_t next_counter_{0};
};

class Receiver {
public:
    explicit Receiver(DirectionKeys keys);
    Bytes decrypt(const Record& record, const Bytes& aad = {});
private:
    DirectionKeys keys_;
    std::uint64_t expected_counter_{0};
};

Bytes make_transcript(const std::string& role,
                      const Key32& d1_ephemeral,
                      const Key32& d2_ephemeral,
                      const Key32& d1_identity,
                      const Key32& d2_identity);

} // namespace sic
