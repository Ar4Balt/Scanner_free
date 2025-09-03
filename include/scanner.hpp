#pragma once
#include <string>
#include <vector>

struct PortResult {
    int port;
    bool open;
    std::string banner;
};

enum class ScanMode { CONNECT, SYN };

class Scanner {
public:
    Scanner(std::string ip, std::vector<int> ports, int threads, int timeout_ms,
            ScanMode mode, bool banner);

    void run();
    void save_json(const std::string& path);
    const std::vector<PortResult>& get_results() const;

private:
    void worker();
    std::string target_ip;
    std::vector<int> ports;
    int num_threads;
    int timeout_ms;
    ScanMode mode;
    bool grab_banner;

    std::vector<PortResult> results;
    std::queue<int> task_queue;
    std::mutex q_mtx, r_mtx;
};
