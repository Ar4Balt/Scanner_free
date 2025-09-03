#include "scanner.hpp"
#include "json_writer.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " -t <target> -p <ports> [-m threads] [-s] [-b] [-o output.json]\n";
        return 1;
    }

    std::string target;
    std::vector<int> ports;
    int threads = 10;
    bool syn_mode = false;
    bool grab_banner = false;
    std::string output_file = "results.json";

    // --- простой парсинг аргументов ---
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-t" && i + 1 < argc) {
            target = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            std::string port_arg = argv[++i];
            size_t dash = port_arg.find('-');
            if (dash != std::string::npos) {
                int start = std::stoi(port_arg.substr(0, dash));
                int end = std::stoi(port_arg.substr(dash + 1));
                for (int p = start; p <= end; ++p) ports.push_back(p);
            } else {
                ports.push_back(std::stoi(port_arg));
            }
        } else if (arg == "-m" && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "-s") {
            syn_mode = true;
        } else if (arg == "-b") {
            grab_banner = true;
        } else if (arg == "-o" && i + 1 < argc) {
            output_file = argv[++i];
        }
    }

    if (target.empty() || ports.empty()) {
        std::cerr << "❌ Target (-t) and ports (-p) are required.\n";
        return 1;
    }

    // --- запуск сканера ---
    Scanner scanner(target, ports, threads, syn_mode, grab_banner);
    auto results = scanner.run();

    // --- JSON вывод ---
    auto json = JsonWriter::to_json(target, results);
    if (JsonWriter::save_to_file(output_file, json)) {
        std::cout << "✅ Results saved to " << output_file << "\n";
    } else {
        std::cerr << "❌ Failed to save results to " << output_file << "\n";
    }

    return 0;
}
