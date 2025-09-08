#include "scanner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// --- Вспомогательная функция для экранирования JSON ---
static std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '\"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default: oss << c; break;
        }
    }
    return oss.str();
}

// --- Конструктор ---
Scanner::Scanner(const std::string& ip, const std::vector<int>& ports,
                 int threads, bool syn_mode, bool banner)
    : target(ip), ports(ports), thread_count(threads),
      syn_scan(syn_mode), banner_grab(banner) {}

// --- Основной запуск ---
std::vector<ScanResult> Scanner::run() {
    // Заполняем очередь портов
    for (int p : ports) task_queue.push(p);

    // Запускаем потоки
    std::vector<std::thread> workers;
    for (int i = 0; i < thread_count; i++) {
        workers.emplace_back(&Scanner::worker, this);
    }

    // Ждём завершения
    for (auto& t : workers) t.join();

    // Сортировка результатов по номеру порта
    std::sort(results.begin(), results.end(),
              [](const ScanResult& a, const ScanResult& b) {
                  return a.port < b.port;
              });

    return results;
}

// --- Сохранение JSON ---
void Scanner::save_json(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return;

    out << "{\n";
    out << "  \"target\": \"" << json_escape(target) << "\",\n";
    out << "  \"results\": [\n";

    for (size_t i = 0; i < results.size(); i++) {
        const auto& r = results[i];
        out << "    {\"port\": " << r.port
            << ", \"open\": " << (r.open ? "true" : "false")
            << ", \"banner\": \"" << json_escape(r.banner) << "\"}";
        if (i + 1 < results.size()) out << ",";
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
}

// --- Поток-воркер ---
void Scanner::worker() {
    while (true) {
        int port;
        {
            std::unique_lock<std::mutex> lock(queue_mtx);
            if (task_queue.empty()) return;
            port = task_queue.front();
            task_queue.pop();
        }

        std::string banner;
        bool is_open = false;

        if (syn_scan) {
#ifdef __linux__
            is_open = scan_tcp_syn(port); // полноценный SYN только на Linux
#else
            is_open = scan_tcp_connect(port, banner); // fallback для macOS
#endif
        } else {
            is_open = scan_tcp_connect(port, banner);
        }

        if (is_open) {
            std::lock_guard<std::mutex> lock(results_mtx);
            results.push_back({port, true, banner});
        }
    }
}

// --- TCP connect scan ---
bool Scanner::scan_tcp_connect(int port, std::string& banner) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    bool success = (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0);

    if (success && banner_grab) {
        banner = grab_banner_from_socket(sock);
    }

    close(sock);
    return success;
}

// --- SYN scan (только Linux, заглушка для macOS) ---
bool Scanner::scan_tcp_syn(int port) {
#ifdef __linux__
    // Здесь должна быть реализация через raw-сокеты
    // Для упрощения сейчас возвращаем false
    (void)port;
    return false;
#else
    (void)port;
    return false;
#endif
}

// --- Banner grabbing ---
std::string Scanner::grab_banner_from_socket(int sock) {
    const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
    send(sock, probe, strlen(probe), 0);

    char buf[256];
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        return std::string(buf);
    }
    return {};
}
