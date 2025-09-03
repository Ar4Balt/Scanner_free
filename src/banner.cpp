#include "banner.hpp"
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <cstring>

bool tcp_connect_with_timeout(const std::string& ip, int port, int timeout_ms, int& out_sock) {
    out_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (out_sock < 0) return false;

    int flags = fcntl(out_sock, F_GETFL, 0);
    fcntl(out_sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int r = connect(out_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (r == 0) return true;
    if (errno != EINPROGRESS) { close(out_sock); return false; }

    fd_set wfds; FD_ZERO(&wfds); FD_SET(out_sock, &wfds);
    timeval tv{ timeout_ms/1000, (timeout_ms%1000)*1000 };

    r = select(out_sock+1, nullptr, &wfds, nullptr, &tv);
    if (r <= 0) { close(out_sock); return false; }

    int err=0; socklen_t len=sizeof(err);
    getsockopt(out_sock, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) { close(out_sock); return false; }

    return true;
}

std::string try_grab_banner(int sock, int port, int timeout_ms) {
    timeval tv{ timeout_ms/1000, (timeout_ms%1000)*1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buf[1024]{};
    std::string banner;

    int n = recv(sock, buf, sizeof(buf)-1, MSG_DONTWAIT);
    if (n > 0) { buf[n] = '\0'; banner += buf; }

    const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
    send(sock, probe, strlen(probe), 0);
    n = recv(sock, buf, sizeof(buf)-1, 0);
    if (n > 0) { buf[n] = '\0'; banner += buf; }

    if (banner.size() > 200) banner.resize(200);
    return banner;
}
