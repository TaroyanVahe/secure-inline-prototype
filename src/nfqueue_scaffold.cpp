#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <cstdlib>
#include <cstring>
#include <iostream>

static int on_packet(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void*) {
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    const std::uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char* data = nullptr;
    const int len = nfq_get_payload(nfa, &data);
    bool selected = false;

    if (len >= static_cast<int>(sizeof(iphdr)) && data) {
        const auto* ip = reinterpret_cast<const iphdr*>(data);
        if (ip->version == 4 && ip->ihl >= 5 && ip->protocol == IPPROTO_TCP) {
            const std::size_t ihl = static_cast<std::size_t>(ip->ihl) * 4;
            if (static_cast<std::size_t>(len) >= ihl + sizeof(tcphdr)) {
                const auto* tcp = reinterpret_cast<const tcphdr*>(data + ihl);
                const unsigned dport = ntohs(tcp->dest);
                const unsigned sport = ntohs(tcp->source);
                // Example selector: TCP port 8443. Replace with explicit flow policy.
                selected = (dport == 8443 || sport == 8443);
            }
        }
    }

    if (selected) {
        // TODO: hand selected packet to a complete proxy/flow-state implementation.
        // This scaffold deliberately does NOT mutate packet bytes.
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char** argv) {
    const unsigned queue_num = argc > 1 ? static_cast<unsigned>(std::strtoul(argv[1], nullptr, 10)) : 42;
    nfq_handle* h = nfq_open();
    if (!h) { std::cerr << "nfq_open failed (run with suitable privileges)\n"; return 1; }
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "warning: nfq_unbind_pf failed\n";
    }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "nfq_bind_pf failed\n"; nfq_close(h); return 1;
    }
    nfq_q_handle* qh = nfq_create_queue(h, static_cast<std::uint16_t>(queue_num), &on_packet, nullptr);
    if (!qh) { std::cerr << "nfq_create_queue failed\n"; nfq_close(h); return 1; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "nfq_set_mode failed\n"; nfq_destroy_queue(qh); nfq_close(h); return 1;
    }
    const int fd = nfq_fd(h);
    unsigned char buffer[65536] __attribute__((aligned));
    std::cout << "NFQUEUE scaffold listening on queue " << queue_num
              << "; selected packets are currently accepted unchanged.\n";
    while (true) {
        const int rv = static_cast<int>(recv(fd, buffer, sizeof(buffer), 0));
        if (rv >= 0) { nfq_handle_packet(h, reinterpret_cast<char*>(buffer), rv); continue; }
        if (errno == EINTR) continue;
        perror("recv"); break;
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
