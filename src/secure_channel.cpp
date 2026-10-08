#include "secure_channel.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <algorithm>
#include <climits>
#include <cstring>
#include <limits>

namespace sic {
namespace {

using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

Key32 raw_private(EVP_PKEY* key) {
    Key32 out{};
    std::size_t n = out.size();
    require(EVP_PKEY_get_raw_private_key(key, out.data(), &n) == 1 && n == out.size(),
            "read raw private key failed");
    return out;
}
Key32 raw_public(EVP_PKEY* key) {
    Key32 out{};
    std::size_t n = out.size();
    require(EVP_PKEY_get_raw_public_key(key, out.data(), &n) == 1 && n == out.size(),
            "read raw public key failed");
    return out;
}

PKey make_raw_private(int type, const Key32& key) {
    EVP_PKEY* p = EVP_PKEY_new_raw_private_key(type, nullptr, key.data(), key.size());
    require(p != nullptr, "create raw private key failed");
    return PKey(p, EVP_PKEY_free);
}
PKey make_raw_public(int type, const Key32& key) {
    EVP_PKEY* p = EVP_PKEY_new_raw_public_key(type, nullptr, key.data(), key.size());
    require(p != nullptr, "create raw public key failed");
    return PKey(p, EVP_PKEY_free);
}

Bytes hkdf(const Bytes& secret, const Bytes& salt, const Bytes& info, std::size_t out_len) {
    EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    require(raw != nullptr, "HKDF context allocation failed");
    PKeyCtx ctx(raw, EVP_PKEY_CTX_free);
    require(EVP_PKEY_derive_init(ctx.get()) > 0, "HKDF init failed");
    require(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) > 0, "HKDF digest failed");
    require(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) > 0,
            "HKDF salt failed");
    require(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(), static_cast<int>(secret.size())) > 0,
            "HKDF key failed");
    require(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) > 0,
            "HKDF info failed");
    Bytes out(out_len);
    std::size_t n = out.size();
    require(EVP_PKEY_derive(ctx.get(), out.data(), &n) > 0 && n == out.size(), "HKDF derive failed");
    return out;
}

Bytes x25519_shared(const Key32& priv, const Key32& peer_pub) {
    auto local = make_raw_private(EVP_PKEY_X25519, priv);
    auto peer = make_raw_public(EVP_PKEY_X25519, peer_pub);
    PKeyCtx ctx(EVP_PKEY_CTX_new(local.get(), nullptr), EVP_PKEY_CTX_free);
    require(ctx != nullptr && EVP_PKEY_derive_init(ctx.get()) > 0, "X25519 derive init failed");
    require(EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) > 0, "X25519 set peer failed");
    std::size_t n = 0;
    require(EVP_PKEY_derive(ctx.get(), nullptr, &n) > 0 && n > 0, "X25519 size query failed");
    Bytes out(n);
    require(EVP_PKEY_derive(ctx.get(), out.data(), &n) > 0, "X25519 shared secret failed");
    out.resize(n);
    return out;
}

Bytes nonce_for(const DirectionKeys& keys, std::uint64_t counter) {
    // 96-bit GCM nonce: 32-bit session/direction prefix || 64-bit big-endian counter.
    Bytes nonce(12);
    std::copy(keys.nonce_prefix.begin(), keys.nonce_prefix.end(), nonce.begin());
    for (int i = 0; i < 8; ++i)
        nonce[4 + i] = static_cast<std::uint8_t>(counter >> (56 - 8 * i));
    return nonce;
}

Bytes gcm_encrypt(const Key32& key, const Bytes& nonce, const Bytes& plaintext,
                  const Bytes& aad, Tag16& tag) {
    require(plaintext.size() <= static_cast<std::size_t>(INT_MAX), "plaintext too large");
    require(aad.size() <= static_cast<std::size_t>(INT_MAX), "AAD too large");
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(ctx != nullptr, "cipher context allocation failed");
    require(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
            "AES-GCM init failed");
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1,
            "AES-GCM nonce length failed");
    require(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) == 1,
            "AES-GCM key/nonce setup failed");
    int n = 0;
    if (!aad.empty())
        require(EVP_EncryptUpdate(ctx.get(), nullptr, &n, aad.data(), static_cast<int>(aad.size())) == 1,
                "AES-GCM AAD failed");
    Bytes out(plaintext.size() + 16);
    int written = 0;
    if (!plaintext.empty()) {
        require(EVP_EncryptUpdate(ctx.get(), out.data(), &written, plaintext.data(),
                                  static_cast<int>(plaintext.size())) == 1, "AES-GCM encrypt failed");
    }
    int final_n = 0;
    require(EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &final_n) == 1, "AES-GCM final failed");
    out.resize(static_cast<std::size_t>(written + final_n));
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) == 1,
            "AES-GCM tag retrieval failed");
    return out;
}

Bytes gcm_decrypt(const Key32& key, const Bytes& nonce, const Bytes& ciphertext,
                  const Bytes& aad, const Tag16& tag) {
    require(ciphertext.size() <= static_cast<std::size_t>(INT_MAX), "ciphertext too large");
    require(aad.size() <= static_cast<std::size_t>(INT_MAX), "AAD too large");
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(ctx != nullptr, "cipher context allocation failed");
    require(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
            "AES-GCM init failed");
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1,
            "AES-GCM nonce length failed");
    require(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) == 1,
            "AES-GCM key/nonce setup failed");
    int n = 0;
    if (!aad.empty())
        require(EVP_DecryptUpdate(ctx.get(), nullptr, &n, aad.data(), static_cast<int>(aad.size())) == 1,
                "AES-GCM AAD failed");
    Bytes out(ciphertext.size() + 16);
    int written = 0;
    if (!ciphertext.empty()) {
        require(EVP_DecryptUpdate(ctx.get(), out.data(), &written, ciphertext.data(),
                                  static_cast<int>(ciphertext.size())) == 1, "AES-GCM decrypt failed");
    }
    Tag16 tag_copy = tag;
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_copy.size(), tag_copy.data()) == 1,
            "AES-GCM tag setup failed");
    int final_n = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &final_n) != 1)
        throw std::runtime_error("AES-GCM authentication failed");
    out.resize(static_cast<std::size_t>(written + final_n));
    return out;
}

} // namespace

Identity generate_ed25519_identity() {
    PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    require(ctx != nullptr && EVP_PKEY_keygen_init(ctx.get()) > 0, "Ed25519 keygen init failed");
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_keygen(ctx.get(), &raw) > 0, "Ed25519 keygen failed");
    PKey key(raw, EVP_PKEY_free);
    return {raw_private(key.get()), raw_public(key.get())};
}
EphemeralX25519 generate_x25519_keypair() {
    PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free);
    require(ctx != nullptr && EVP_PKEY_keygen_init(ctx.get()) > 0, "X25519 keygen init failed");
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_keygen(ctx.get(), &raw) > 0, "X25519 keygen failed");
    PKey key(raw, EVP_PKEY_free);
    return {raw_private(key.get()), raw_public(key.get())};
}
Key32 ed25519_public_from_private(const Key32& private_key) {
    auto key = make_raw_private(EVP_PKEY_ED25519, private_key);
    return raw_public(key.get());
}
Key32 x25519_public_from_private(const Key32& private_key) {
    auto key = make_raw_private(EVP_PKEY_X25519, private_key);
    return raw_public(key.get());
}

Bytes sign_transcript(const Key32& ed25519_private, const Bytes& transcript) {
    auto key = make_raw_private(EVP_PKEY_ED25519, ed25519_private);
    MdCtx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(ctx != nullptr && EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1,
            "Ed25519 sign init failed");
    std::size_t n = 0;
    require(EVP_DigestSign(ctx.get(), nullptr, &n, transcript.data(), transcript.size()) == 1,
            "Ed25519 signature size failed");
    Bytes sig(n);
    require(EVP_DigestSign(ctx.get(), sig.data(), &n, transcript.data(), transcript.size()) == 1,
            "Ed25519 sign failed");
    sig.resize(n);
    return sig;
}
bool verify_transcript(const Key32& ed25519_public, const Bytes& transcript, const Bytes& signature) {
    auto key = make_raw_public(EVP_PKEY_ED25519, ed25519_public);
    MdCtx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                            transcript.data(), transcript.size()) == 1;
}

SessionKeys derive_session_keys(const Key32& local_ephemeral_private,
                                const Key32& peer_ephemeral_public,
                                const Bytes& transcript_context) {
    Bytes secret = x25519_shared(local_ephemeral_private, peer_ephemeral_public);
    Bytes salt = transcript_context; // context must be canonical and include both identities/ephemerals
    const std::string info = "secure-inline-prototype/v1";
    Bytes material = hkdf(secret, salt, Bytes(info.begin(), info.end()), 72);
    SessionKeys out{};
    std::copy_n(material.begin(), 32, out.device1_to_device2.aes_key.begin());
    std::copy_n(material.begin() + 32, 4, out.device1_to_device2.nonce_prefix.begin());
    std::copy_n(material.begin() + 36, 32, out.device2_to_device1.aes_key.begin());
    std::copy_n(material.begin() + 68, 4, out.device2_to_device1.nonce_prefix.begin());
    // Best-effort clearing of intermediate secret bytes.
    std::fill(secret.begin(), secret.end(), 0);
    std::fill(material.begin(), material.end(), 0);
    return out;
}

Bytes make_transcript(const std::string& role, const Key32& d1_ephemeral,
                      const Key32& d2_ephemeral, const Key32& d1_identity,
                      const Key32& d2_identity) {
    Bytes out;
    auto append = [&out](const std::uint8_t* p, std::size_t n) { out.insert(out.end(), p, p + n); };
    const std::uint32_t len = static_cast<std::uint32_t>(role.size());
    out.push_back(static_cast<std::uint8_t>(len >> 24));
    out.push_back(static_cast<std::uint8_t>(len >> 16));
    out.push_back(static_cast<std::uint8_t>(len >> 8));
    out.push_back(static_cast<std::uint8_t>(len));
    out.insert(out.end(), role.begin(), role.end());
    append(d1_ephemeral.data(), d1_ephemeral.size());
    append(d2_ephemeral.data(), d2_ephemeral.size());
    append(d1_identity.data(), d1_identity.size());
    append(d2_identity.data(), d2_identity.size());
    return out;
}

Sender::Sender(DirectionKeys keys) : keys_(keys) {}
Record Sender::encrypt(const Bytes& plaintext, const Bytes& aad) {
    if (next_counter_ == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("record counter exhausted; rekey required");
    Record r;
    r.counter = next_counter_++;
    r.ciphertext = gcm_encrypt(keys_.aes_key, nonce_for(keys_, r.counter), plaintext, aad, r.tag);
    return r;
}
Receiver::Receiver(DirectionKeys keys) : keys_(keys) {}
Bytes Receiver::decrypt(const Record& record, const Bytes& aad) {
    // Ordered record stream prototype. A production transport needs a bounded replay window
    // and careful treatment of reordering; this receiver rejects gaps and duplicates.
    if (record.counter != expected_counter_)
        throw std::runtime_error("replay, out-of-order record, or counter gap");
    Bytes plain = gcm_decrypt(keys_.aes_key, nonce_for(keys_, record.counter),
                              record.ciphertext, aad, record.tag);
    ++expected_counter_;
    return plain;
}
} // namespace sic
