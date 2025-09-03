#include "utils.hpp"
#include <sstream>
#include <iomanip>
#include <set>
#include <netdb.h>
#include <arpa/inet.h>

uint64_t now_epoch_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (auto c : s) {
        switch (c) {
            case '\"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default: o << c; break;
        }
    }
    return o.str();
}

std::optional<std::string> resolve_target_to_ipv4(std::string host) {
    addrinfo hints{}; hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return std::nullopt;
    char ip[INET_ADDRSTRLEN]{};
    auto* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &(sin->sin_addr), ip, sizeof(ip));
    freeaddrinfo(res);
    return std::string(ip);
}

std::vector<int> parse_ports(const std::string& spec) {
    std::set<int> result;
    std::stringstream ss(spec);
    std::string part;
    while (std::getline(ss, part, ',')) {
        auto dash = part.find('-');
        if (dash == std::string::npos) {
            int v = std::stoi(part);
            if (v >= 1 && v <= 65535) result.insert(v);
        } else {
            int a = std::stoi(part.substr(0, dash));
            int b = std::stoi(part.substr(dash + 1));
            if (a > b) std::swap(a, b);
            for (int x = a; x <= b; ++x) result.insert(x);
        }
    }
    return {result.begin(), result.end()};
}
