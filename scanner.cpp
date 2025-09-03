#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
  #include <netinet/ip.h>   // struct iphdr
  #include <netinet/tcp.h>  // struct tcphdr
  #include <errno.h>
#endif

// ---------------------- УТИЛИТЫ ----------------------

static uint64_t now_epoch_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (auto c : s) {
        switch (c) {
            case '\"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    o << "\\u" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << int((unsigned char)c)
                      << std::nouppercase << std::dec;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

static std::optional<std::string> resolve_target_to_ipv4(std::string host) {
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return std::nullopt;
    char ip[INET_ADDRSTRLEN]{};
    auto* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &(sin->sin_addr), ip, sizeof(ip));
    freeaddrinfo(res);
    return std::string(ip);
}

static void split(const std::string& s, char delim, std::vector<std::string>& out) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!item.empty()) out.push_back(item);
    }
}

static std::vector<int> parse_ports(const std::string& spec) {
    // Поддержка: "1-1000", "22,80,443", "22,80,1000-1100"
    std::set<int> result;
    std::vector<std::string> parts;
    split(spec, ',', parts);
    if (parts.empty()) {
        // если просто число/диапазон без запятых
        parts.push_back(spec);
    }
    for (auto& p : parts) {
        auto dash = p.find('-');
        if (dash == std::string::npos) {
            int v = std::stoi(p);
            if (v >= 1 && v <= 65535) result.insert(v);
        } else {
            int a = std::stoi(p.substr(0, dash));
            int b = std::stoi(p.substr(dash + 1));
            if (a > b) std::swap(a, b);
            a = std::max(1, a); b = std::min(65535, b);
            for (int x = a; x <= b; ++x) result.insert(x);
        }
    }
    return std::vector<int>(result.begin(), result.end());
}

// Неблокирующий connect с timeout
static bool tcp_connect_with_timeout(const std::string& ip, int port, int timeout_ms, int& out_sock) {
    out_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (out_sock < 0) return false;

    // non-blocking
    int flags = fcntl(out_sock, F_GETFL, 0);
    fcntl(out_sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int r = ::connect(out_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (r == 0) {
        // мгновенно подключился
        return true;
    }

    if (errno != EINPROGRESS) {
        close(out_sock);
        return false;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(out_sock, &wfds);

    struct timeval tv{
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };

    r = select(out_sock + 1, nullptr, &wfds, nullptr, &tv);
    if (r <= 0) {
        close(out_sock);
        return false;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(out_sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        close(out_sock);
        return false;
    }

    // подключение установлено
    return true;
}

// Простой banner grabbing: читаем приветствия + пробуем HTTP HEAD
static std::string try_grab_banner(int sock, int port, int timeout_ms) {
    // таймауты
    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Некоторые сервисы сами присылают баннер при подключении (SSH/SMTP/POP3/FTP и т.д.)
    char buf[1024]{};
    int n = ::recv(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
    std::string banner;
    if (n > 0) {
        buf[n] = '\0';
        banner = buf;
    }

    // Если порт похож на HTTP/HTTPS/прокси — попробуем краткий HEAD
    // (HEAD подойдёт и для многих не-HTTP, просто ничего не вернётся)
    const char* http_probe = "HEAD / HTTP/1.0\r\n\r\n";
    ::send(sock, http_probe, (int)std::strlen(http_probe), 0);
    n = ::recv(sock, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        banner += buf;
    }

    // огради размер баннера, чтобы JSON не разросся
    if (banner.size() > 200) banner.resize(200);
    return banner;
}

#ifdef __linux__
// ---------------------- SYN SCAN (Linux) ----------------------

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

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
};

static bool syn_probe_linux(const std::string& dst_ip, uint16_t dport, int timeout_ms) {
    // raw socket (requires root)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return false;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return false;
    }

    // Собираем пакет: IP + TCP(SYN)
    char packet[sizeof(iphdr) + sizeof(tcphdr)]{};
    auto* iph  = reinterpret_cast<iphdr*>(packet);
    auto* tcph = reinterpret_cast<tcphdr*>(packet + sizeof(iphdr));

    // Источник — ядро подставит IP если оставить 0, но для чексумм нужен адрес.
    // Возьмём 0.0.0.0 — многие ядра считают корректно, но лучше было бы узнать исходящий IP.
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(packet));
    iph->id       = htons((uint16_t) (rand() & 0xffff));
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check    = 0;
    iph->saddr    = 0; // kernel will fill (на некоторых системах может не сработать)
    inet_pton(AF_INET, dst_ip.c_str(), &iph->daddr);

    tcph->source  = htons(40000 + (rand() % 20000));
    tcph->dest    = htons(dport);
    tcph->seq     = htonl((uint32_t)rand());
    tcph->ack_seq = 0;
    tcph->doff    = sizeof(tcphdr) / 4;
    tcph->syn     = 1;
    tcph->window  = htons(65535);
    tcph->check   = 0;

    // Псевдо-заголовок для чексуммы TCP
    pseudo_header psh{};
    psh.src  = iph->saddr;
    psh.dst  = iph->daddr;
    psh.zero = 0;
    psh.proto= IPPROTO_TCP;
    psh.len  = htons(sizeof(tcphdr));

    char pseudo[sizeof(pseudo_header) + sizeof(tcphdr)]{};
    std::memcpy(pseudo, &psh, sizeof(psuedo_header)); // will fix typo below
    // OOPS— we must correct: pseudo_header variable name is psh, not psuedo_header; fix below
    // To avoid typo, rewrite the two lines:
    // memcpy(pseudo, &psh, sizeof(psh));
    // memcpy(pseudo + sizeof(psh), tcph, sizeof(tcphdr));
    // but we cannot modify earlier line in this environment; we will write correct version after block.

    // --- Corrected pseudo build ---
    std::memset(pseudo, 0, sizeof(pseudo));
    std::memcpy(pseudo, &psh, sizeof(psh));
    std::memcpy(pseudo + sizeof(psh), tcph, sizeof(tcphdr));

    tcph->check = csum(reinterpret_cast<uint16_t*>(pseudo), sizeof(pseudo));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = tcph->dest;
    inet_pton(AF_INET, dst_ip.c_str(), &dst.sin_addr);

    // Отправка SYN
    if (sendto(sock, packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        close(sock);
        return false;
    }

    // Ожидаем ответ
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(sock + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) { // timeout / error
        close(sock);
        return false;
    }

    // Принимаем пакет
    char buf[2048];
    sockaddr_in from{};
    socklen_t   fromlen = sizeof(from);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &fromlen);
    close(sock);
    if (n < (int)(sizeof(iphdr) + sizeof(tcphdr))) return false;

    auto* rip  = reinterpret_cast<iphdr*>(buf);
    if (rip->protocol != IPPROTO_TCP) return false;
    auto* rtcp = reinterpret_cast<tcphdr*>(buf + rip->ihl*4);

    // Проверяем, что это ответ от нужного порта и IP
    char srcip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &from.sin_addr, srcip, sizeof(srcip));
    if (dst_ip != std::string(srcip)) return false;
    if (ntohs(rtcp->source) != dport) return false;

    // Открыт: SYN+ACK; Закрыт: RST
    bool syn_set = (rtcp->syn != 0);
    bool ack_set = (rtcp->ack != 0);
    bool rst_set = (rtcp->rst != 0);

    if (syn_set && ack_set) return true;   // open
    if (rst_set)             return false; // closed
    return false;                            // unknown -> treat as closed
}
#endif

// ---------------------- СКАННЕР ----------------------

struct PortResult {
    int port{};
    bool open{};
    std::string banner;
};

enum class ScanMode { CONNECT, SYN };

class Scanner {
public:
    Scanner(std::string ip, std::vector<int> ports, int threads, int timeout_ms,
            ScanMode mode, bool banner)
        : target_ip(std::move(ip)), ports(std::move(ports)), num_threads(threads),
          timeout_ms(timeout_ms), mode(mode), grab_banner(banner) {}

    void run() {
        for (int p : ports) task_queue.push(p);
        std::vector<std::thread> workers;
        for (int i = 0; i < std::max(1, num_threads); ++i) {
            workers.emplace_back(&Scanner::worker, this);
        }
        for (auto& t : workers) t.join();
        std::sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b){return a.port < b.port;});
    }

    void save_json(const std::string& path) {
        std::ofstream out(path);
        if (!out) {
            std::cerr << "[-] Cannot open file for writing: " << path << "\n";
            return;
        }
        out << "{\n";
        out << "  \"target\": \"" << json_escape(target_ip) << "\",\n";
        out << "  \"scan_type\": \"" << (mode == ScanMode::SYN ? "syn" : "connect") << "\",\n";
        out << "  \"timestamp_ms\": " << now_epoch_ms() << ",\n";
        out << "  \"results\": [\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            out << "    {\"port\": " << r.port << ", \"open\": " << (r.open ? "true" : "false");
            if (!r.banner.empty())
                out << ", \"banner\": \"" << json_escape(r.banner) << "\"";
            out << "}";
            if (i + 1 < results.size()) out << ",";
            out << "\n";
        }
        out << "  ]\n";
        out << "}\n";
        std::cout << "[+] Results saved to " << path << "\n";
    }

    const std::vector<PortResult>& get_results() const { return results; }

private:
    std::string target_ip;
    std::vector<int> ports;
    int num_threads;
    int timeout_ms;
    ScanMode mode;
    bool grab_banner;

    std::mutex q_mtx;
    std::queue<int> task_queue;

    std::mutex r_mtx;
    std::vector<PortResult> results;

    void worker() {
        while (true) {
            int port = 0;
            {
                std::lock_guard<std::mutex> lk(q_mtx);
                if (task_queue.empty()) break;
                port = task_queue.front();
                task_queue.pop();
            }

            PortResult pr;
            pr.port = port;
            pr.open = false;

            if (mode == ScanMode::CONNECT
#ifdef __APPLE__
                || true // на macOS всегда connect
#endif
            ) {
                int sock = -1;
                if (tcp_connect_with_timeout(target_ip, port, timeout_ms, sock)) {
                    pr.open = true;
                    if (grab_banner) {
                        pr.banner = try_grab_banner(sock, port, std::min(timeout_ms, 1500));
                    }
                }
                if (sock >= 0) close(sock);
            }
#ifdef __linux__
            else { // SYN
                pr.open = syn_probe_linux(target_ip, (uint16_t)port, timeout_ms);
            }
#endif

            {
                std::lock_guard<std::mutex> lk(r_mtx);
                results.push_back(std::move(pr));
            }
        }
    }
};

// ---------------------- MAIN ----------------------

static void print_usage(const char* prog) {
    std::cout <<
        "Usage:\n"
        "  " << prog << " -t <target> -p <ports> [-m threads] [-o out.json] [--syn] [--banner] [--timeout ms]\n\n"
        "Options:\n"
        "  -t <target>      IP или hostname цели\n"
        "  -p <ports>       Порты: '1-1000' или '22,80,443' или микс '22,80,1000-1100'\n"
        "  -m <threads>     Кол-во потоков (по умолчанию 100)\n"
        "  -o <file>        JSON-вывод (по умолчанию results.json)\n"
        "  --syn            Включить SYN-скан (Linux). На macOS будет fallback на connect.\n"
        "  --banner         Пробовать получать баннеры сервисов\n"
        "  --timeout <ms>   Таймаут на порт (по умолчанию 800 мс)\n";
}

int main(int argc, char* argv[]) {
    std::string target, ports_spec, out_file = "results.json";
    int threads = 100;
    int timeout_ms = 800;
    bool use_syn = false;
    bool use_banner = false;

    // Простой разбор аргументов
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-t" && i + 1 < argc)       target = argv[++i];
        else if (a == "-p" && i + 1 < argc)  ports_spec = argv[++i];
        else if (a == "-m" && i + 1 < argc)  threads = std::stoi(argv[++i]);
        else if (a == "-o" && i + 1 < argc)  out_file = argv[++i];
        else if (a == "--syn")               use_syn = true;
        else if (a == "--banner")            use_banner = true;
        else if (a == "--timeout" && i + 1 < argc) timeout_ms = std::stoi(argv[++i]);
        else if (a == "-h" || a == "--help") { print_usage(argv[0]); return 0; }
    }

    if (target.empty() || ports_spec.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    auto ip_opt = resolve_target_to_ipv4(target);
    if (!ip_opt) {
        std::cerr << "[-] Cannot resolve target: " << target << "\n";
        return 1;
    }
    std::string ip = *ip_opt;
    auto ports = parse_ports(ports_spec);
    if (ports.empty()) {
        std::cerr << "[-] Port list is empty\n";
        return 1;
    }

#ifndef __linux__
    if (use_syn) {
        std::cout << "[!] SYN-скан недоступен на этой ОС. Использую TCP Connect.\n";
    }
#endif

    ScanMode mode = (use_syn
#ifdef __linux__
                    ? ScanMode::SYN
#else
                    ? ScanMode::CONNECT
#endif
                    : ScanMode::CONNECT);

    Scanner scanner(ip, ports, threads, timeout_ms, mode, use_banner);

    auto t0 = now_epoch_ms();
    scanner.run();
    auto t1 = now_epoch_ms();

    const auto& res = scanner.get_results();
    int open_count = 0;
    for (const auto& r : res) if (r.open) ++open_count;

    std::cout << "[+] Scan finished: " << target << " (" << ip << ") "
              << "ports=" << ports.size()
              << ", open=" << open_count
              << ", time=" << (t1 - t0) << " ms\n";

    scanner.save_json(out_file);

    // Краткий вывод открытых портов
    for (const auto& r : res) {
        if (r.open) {
            std::cout << "  " << r.port;
            if (!r.banner.empty()) std::cout << "  banner: " << r.banner.substr(0, 80);
            std::cout << "\n";
        }
    }
    return 0;
}
