#pragma once
#include <string>
#include <vector>
#include "scanner.hpp"

namespace JsonWriter {
    std::string to_json(const std::string& target, const std::vector<ScanResult>& results);
    bool save_to_file(const std::string& filename, const std::string& json_data);
}
