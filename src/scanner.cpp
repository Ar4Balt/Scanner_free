#include "scanner.hpp"
#include "banner.hpp"
#include "utils.hpp"

#ifdef __linux__
#include "synscan.hpp"
#endif

#include <fstream>
#include <thread>
#include <algorithm>
#include <unistd.h>

Scanner::Scanner(std::string ip, std::vector<int> ports, int threads, int timeout_ms,
                 ScanMode mode, bool banner)
    : target_ip(std::move(ip)), ports(std::move(ports)), num_threads(threads),
      timeout_ms(timeout_ms), mode(mode), grab_banner(banner) {}

void Scanner::run() {
    for (int p : ports) task_queue.push(p);
    std::vector<std::thread> workers;
    for (int i = 0; i < num_threads; i++) workers.emplace_back(&Scanner::worker, this);
    for (auto& t : workers) t.join();

    std::sort(results.begin(), results.end(), [](auto& a, auto& b){return a.port < b.port;});
}

void Scanner::save_json(const std::string& path) {
    std::ofstream out(path);
    out << "{\n";
    out << "  \"target\": \"" << json_escape(target_ip) << "\",\n";
    out << "  \"results\": [\n";
    for (size_t i=0;i<results.size();i++) {
        auto& r=results[i];
        out << "    {\"port\": " << r.port << ", \"open\": " << (r.open?"true":"false");
        if (!r.banner.empty()) out << ", \"banner\": \"" << json_escape(r.banner) << "\"";
        out << "}";
        if (i+1<results.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n}\n";
}

const std::vector<PortResult>& Scanner::get_results() const { return results; }

void Scanner::worker() {
    while (true) {
        int port=0;
        {
            std::lock_guard<std::mutex> lock(q_mtx);
            if (task_queue.empty()) break;
            port = task_queue.front(); task_queue.pop();
        }

        PortResult pr{port,false,""};
        int sock=-1;
        if (mode==ScanMode::CONNECT
#ifdef __APPLE__
            || true
#endif
        ) {
            if (tcp_connect_with_timeout(target_ip, port, timeout_ms, sock)) {
                pr.open=true;
                if (grab_banner) pr.banner=try_grab_banner(sock,port,timeout_ms);
            }
            if (sock>=0) close(sock);
        }
#ifdef __linux__
        else {
            pr.open = syn_probe_linux(target_ip, port, timeout_ms);
        }
#endif
        std::lock_guard<std::mutex> lock(r_mtx);
        results.push_back(pr);
    }
}
