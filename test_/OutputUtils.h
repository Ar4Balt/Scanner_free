#ifndef OUTPUTUTILS_H
#define OUTPUTUTILS_H

#include <vector>
#include <string>
#include <atomic>

void clearScreen();
void printProgress(int current, int total);
void printScanSummary(const std::vector<std::string>& activeHosts);

#endif // OUTPUTUTILS_H
