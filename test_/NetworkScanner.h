#ifndef NETWORKSCANNER_H
#define NETWORKSCANNER_H

#include <string>
#include <vector>
#include <atomic>

class NetworkScanner {
public:
    NetworkScanner(const std::string& subnet, const std::vector<int>& ports, int maxConcurrency);

    void startScan(std::vector<std::string>& activeHosts, std::atomic<int>& checkedCount, std::atomic<bool>& stopFlag);

private:
    bool checkPort(const std::string& ip, int port);
    void scanHost(const std::string& ip, std::vector<std::string>& activeHosts, std::atomic<int>& checkedCount, int total, std::atomic<bool>& stopFlag);

    std::string m_subnet;
    std::vector<int> m_ports;
    int m_maxConcurrency;
};

#endif // NETWORKSCANNER_H
