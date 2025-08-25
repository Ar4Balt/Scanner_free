#include "NetworkScanner.h"

#include <iostream>
#include <future>
#include <mutex>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

std::mutex hostsMutex, outputMutex;

NetworkScanner::NetworkScanner(const std::string& subnet, const std::vector<int>& ports, int maxConcurrency)
    : m_subnet(subnet), m_ports(ports), m_maxConcurrency(maxConcurrency) {}

bool NetworkScanner::checkPort(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Устанавливаем сокет в неблокирующий режим
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int res = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    timeval tv{};
    tv.tv_sec = 1; // таймаут 1 секунда
    tv.tv_usec = 0;

    res = select(sock + 1, NULL, &fdset, NULL, &tv);
    if (res > 0) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        close(sock);
        return (so_error == 0);
    }

    close(sock);
    return false;
}

void NetworkScanner::scanHost(const std::string& ip, std::vector<std::string>& activeHosts,
                              std::atomic<int>& checkedCount, int total, std::atomic<bool>& stopFlag) {
    if (stopFlag) return;

    bool reachable = false;
    for (int port : m_ports) {
        if (stopFlag) return;
        if (checkPort(ip, port)) {
            reachable = true;
            break;
        }
    }

    if (reachable) {
        std::lock_guard<std::mutex> lock(hostsMutex);
        activeHosts.push_back(ip + " - Host is reachable on port(s)");
    }
    checkedCount++;
}
        
void NetworkScanner::startScan(std::vector<std::string>& activeHosts, std::atomic<int>& checkedCount, std::atomic<bool>& stopFlag) {
    const int total = 254;
    std::vector<std::future<void>> futures;
    int currentIP = 1;

    while (currentIP <= total && !stopFlag) {
        if ((int)futures.size() < m_maxConcurrency) {
            std::string ip = m_subnet + std::to_string(currentIP++);
            futures.push_back(std::async(std::launch::async, &NetworkScanner::scanHost, this,
                                         ip, std::ref(activeHosts), std::ref(checkedCount), total, std::ref(stopFlag)));
        } else {
            for (auto it = futures.begin(); it != futures.end();) {
                if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                    it->get();
                    it = futures.erase(it);
                } else {
                    ++it;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    for (auto& f : futures) {
        f.get();
    }
}
