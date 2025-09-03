#include "synscan.hpp"

#ifdef __linux__
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <iostream>

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

static uint16_t csum(const uint16_t* ptr, size_t nbytes) {
    uint32_t sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        uint16_t odd = 0;
        *(uint8_t*)(&odd) = *(uint8_t*)ptr;
        sum += odd;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

bool syn_probe_linux(const std::string& dst_ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return false;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return false;
    }

    char packet[sizeof(iphdr) + sizeof(tcphdr)]{};
    auto* iph = (iphdr*)packet;
    auto* tcph = (tcphdr*)(packet + sizeof(iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(packet));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, dst_ip.c_str(), &iph->daddr);

    tcph->source = htons(40000 + rand() % 20000);
    tcph->dest = htons(port);
    tcph->seq = htonl(rand());
    tcph->doff = sizeof(tcphdr) / 4;
    tcph->syn = 1;
    tcph->window = htons(65535);

    pseudo_header psh{};
    psh.src = iph->saddr;
    psh.dst = iph->daddr;
    psh.proto = IPPROTO_TCP;
    psh.len = htons(sizeof(tcphdr));

    char pseudo[sizeof(psh) + sizeof(tcphdr)];
    memcpy(pseudo, &psh, sizeof(psh));
    memcpy(pseudo + sizeof(psh), tcph, sizeof(tcphdr));
    tcph->check = csum((uint16_t*)pseudo, sizeof(pseudo));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = tcph->dest;
    inet_pton(AF_INET, dst_ip.c_str(), &dst.sin_addr);

    if (sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
        close(sock);
        return false;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};

    int sel = select(sock + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) { close(sock); return false; }

    char buf[2048];
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &fromlen);
    close(sock);
    if (n < (int)(sizeof(iphdr) + sizeof(tcphdr))) return false;

    auto* rip = (iphdr*)buf;
    if (rip->protocol != IPPROTO_TCP) return false;
    auto* rtcp = (tcphdr*)(buf + rip->ihl * 4);

    bool syn_set = rtcp->syn;
    bool ack_set = rtcp->ack;
    bool rst_set = rtcp->rst;

    return (syn_set && ack_set) && !rst_set;
}
#endif
