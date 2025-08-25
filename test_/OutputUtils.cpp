#include "OutputUtils.h"
#include <iostream>
#include <iomanip>
#include <mutex>

static std::mutex outputMutex;

void clearScreen() {
    std::lock_guard<std::mutex> lock(outputMutex);
    std::cout << "\033[2J\033[H";  // Очистка экрана и установка курсора в начало
}

void printProgress(int current, int total) {
    int barWidth = 40;
    float progress = float(current) / total;
    int pos = barWidth * progress;

    std::lock_guard<std::mutex> lock(outputMutex);
    std::cout << "\033[2K\r"; // Очистить текущую строку
    std::cout << "[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << int(progress * 100.0) << "% (" << current << "/" << total << ")";
    std::cout.flush();
}

void printScanSummary(const std::vector<std::string>& activeHosts) {
    std::cout << "\nScan Summary:\n";
    std::cout << "-----------------------------------\n";
    if (activeHosts.empty()) {
        std::cout << "No active hosts found in the scanned range.\n";
    } else {
        std::cout << "Total active hosts found: " << activeHosts.size() << "\n\n";
        std::cout << std::left << std::setw(5) << "No."
                  << std::setw(40) << "Host IP and Info" << "\n";
        std::cout << "-----------------------------------\n";

        int index = 1;
        for (const auto& host : activeHosts) {
            std::cout << std::setw(5) << index++ << std::setw(40) << host << "\n";
        }
    }
    std::cout << "-----------------------------------\n";
}
