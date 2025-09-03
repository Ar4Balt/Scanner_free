#pragma once
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>

// Результат по одному порту
struct ScanResult {
    int port;
    bool open;
    std::string banner;
};

class Scanner {
public:
    Scanner(const std::string& target, const std::vector<int>& ports,
            int threads, bool syn_mode, bool grab_banner);

    std::vector<ScanResult> run();
    void save_json(const std::string& path) const;

private:
    std::string target;
    std::vector<int> ports;
    int thread_count;
    bool syn_scan;
    bool banner_grab;

    std::queue<int> task_queue;
    mutable std::mutex queue_mtx;
    std::condition_variable cv;
    std::atomic<bool> done{false};

    std::vector<ScanResult> results;
    mutable std::mutex results_mtx;

    void worker();
    bool scan_tcp_connect(int port, std::string& banner);
    bool scan_tcp_syn(int port);
    std::string grab_banner_from_socket(int sock);
};
