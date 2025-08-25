#include <iostream>
#include <vector>
#include <string>
#include <atomic>
#include <csignal>
#include <thread>
#include <mutex>          // <-- обязательно

#include "NetworkScanner.h"
#include "OutputUtils.h"

std::atomic<bool> stopFlag(false);
std::mutex networkScannerMutex;  // <-- добавляем

void signalHandler(int /*signum*/) {
    stopFlag = true;
}

int main() {
    std::signal(SIGINT, signalHandler);

    std::string subnet = "172.16.250.";
    std::vector<int> ports = {22, 80, 443};
    int maxConcurrency = 100;

    NetworkScanner scanner(subnet, ports, maxConcurrency);

    std::vector<std::string> activeHosts;
    std::atomic<int> checkedCount(0);

    std::thread scanThread([&]() {
        scanner.startScan(activeHosts, checkedCount, stopFlag);
    });

    const int total = 254;

    while (!stopFlag && checkedCount < total) {
        clearScreen();

        {
            std::lock_guard<std::mutex> lock(networkScannerMutex);  // <-- теперь корректно
            for (const auto& host : activeHosts) {
                std::cout << host << std::endl;
            }
        }
        printProgress(checkedCount, total);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (scanThread.joinable())
        scanThread.join();

    clearScreen();
    printScanSummary(activeHosts);

    std::cout << (stopFlag ? "Scan interrupted by user.\n" : "Scan completed successfully.\n");

    return 0;
}
