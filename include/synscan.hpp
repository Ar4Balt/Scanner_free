#pragma once
#include <string>

#ifdef __linux__
bool syn_probe_linux(const std::string& dst_ip, int port, int timeout_ms);
#endif
