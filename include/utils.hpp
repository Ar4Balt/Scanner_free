#pragma once
#include <string>
#include <vector>
#include <optional>
#include <chrono>

uint64_t now_epoch_ms();
std::string json_escape(const std::string& s);
std::optional<std::string> resolve_target_to_ipv4(std::string host);
std::vector<int> parse_ports(const std::string& spec);
