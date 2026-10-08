#include "secure_channel.hpp"
#include <cassert>
#include <iostream>
#include <string>

int main() {
    const auto a = sic::generate_ed25519_identity();
    const auto b = sic::generate_ed25519_identity();
    const auto ae = sic::generate_x25519_keypair();
    const auto be = sic::generate_x25519_keypair();
    const auto t = sic::make_transcript("test-v1", ae.public_key, be.public_key,
                                        a.ed25519_public, b.ed25519_public);
    auto sig = sic::sign_transcript(a.ed25519_private, t);
    assert(sic::verify_transcript(a.ed25519_public, t, sig));
    assert(!sic::verify_transcript(b.ed25519_public, t, sig));

    const auto ka = sic::derive_session_keys(ae.private_key, be.public_key, t);
    const auto kb = sic::derive_session_keys(be.private_key, ae.public_key, t);
    assert(ka.device1_to_device2.aes_key == kb.device1_to_device2.aes_key);
    assert(ka.device1_to_device2.nonce_prefix == kb.device1_to_device2.nonce_prefix);

    sic::Sender tx(ka.device1_to_device2);
    sic::Receiver rx(kb.device1_to_device2);
    const sic::Bytes p1{'a','l','p','h','a'};
    const sic::Bytes p2{'b','e','t','a'};
    const sic::Bytes aad{'I','P','v','4'};
    auto r1 = tx.encrypt(p1, aad);
    auto r2 = tx.encrypt(p2, aad);
    assert(r1.counter == 0 && r2.counter == 1);
    assert(rx.decrypt(r1, aad) == p1);
    assert(rx.decrypt(r2, aad) == p2);

    auto bad = tx.encrypt(p1, aad);
    bad.tag[0] ^= 0x80;
    bool rejected = false;
    try { (void)rx.decrypt(bad, aad); } catch (...) { rejected = true; }
    assert(rejected);

    auto replay_rx = sic::Receiver(kb.device1_to_device2);
    (void)replay_rx.decrypt(r1, aad);
    rejected = false;
    try { (void)replay_rx.decrypt(r1, aad); } catch (...) { rejected = true; }
    assert(rejected);

    std::cout << "All crypto tests passed\n";
    return 0;
}
