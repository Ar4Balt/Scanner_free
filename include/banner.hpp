#pragma once
#include <string>

bool tcp_connect_with_timeout(const std::string& ip, int port, int timeout_ms, int& out_sock);
std::string try_grab_banner(int sock, int port, int timeout_ms);
