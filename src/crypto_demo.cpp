#include "secure_channel.hpp"
#include <iostream>
#include <string>

int main() {
    try {
        // Self-contained demo. Production deployments must load/pin provisioned identity keys.
        const auto d1_id = sic::generate_ed25519_identity();
        const auto d2_id = sic::generate_ed25519_identity();
        const auto d1_eph = sic::generate_x25519_keypair();
        const auto d2_eph = sic::generate_x25519_keypair();

        const auto transcript = sic::make_transcript("D1-authenticates-D2-v1",
            d1_eph.public_key, d2_eph.public_key, d1_id.ed25519_public, d2_id.ed25519_public);
        const auto sig_d1 = sic::sign_transcript(d1_id.ed25519_private, transcript);
        const auto sig_d2 = sic::sign_transcript(d2_id.ed25519_private, transcript);
        if (!sic::verify_transcript(d1_id.ed25519_public, transcript, sig_d1) ||
            !sic::verify_transcript(d2_id.ed25519_public, transcript, sig_d2))
            throw std::runtime_error("handshake signature verification failed");

        const auto k1 = sic::derive_session_keys(d1_eph.private_key, d2_eph.public_key, transcript);
        const auto k2 = sic::derive_session_keys(d2_eph.private_key, d1_eph.public_key, transcript);

        sic::Sender sender(k1.device1_to_device2);
        sic::Receiver receiver(k2.device1_to_device2);
        const std::string message = "hello securely from Device1 to Device2";
        const sic::Bytes plaintext(message.begin(), message.end());
        const sic::Bytes aad{'T','C','P','4'};
        const auto record = sender.encrypt(plaintext, aad);
        const auto recovered = receiver.decrypt(record, aad);
        const std::string decoded(recovered.begin(), recovered.end());
        std::cout << "Handshake signatures verified\n";
        std::cout << "AES-256-GCM record counter: " << record.counter << "\n";
        std::cout << "Plaintext recovered: " << decoded << "\n";

        try {
            (void)receiver.decrypt(record, aad);
            std::cerr << "ERROR: replay was not rejected\n";
            return 2;
        } catch (const std::exception&) {
            std::cout << "Replay rejected\n";
        }
        return decoded == message ? 0 : 3;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
}
