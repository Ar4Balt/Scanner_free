#include "scanner.hpp"
#include "utils.hpp"
#include <iostream>

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " -t <target> -p <ports> [-m threads] [-o out.json] [--syn] [--banner]\n";
}

int main(int argc, char* argv[]) {
    std::string target, ports_spec, out_file="results.json";
    int threads=100, timeout_ms=800;
    bool use_syn=false, use_banner=false;

    for (int i=1;i<argc;i++) {
        std::string a=argv[i];
        if (a=="-t" && i+1<argc) target=argv[++i];
        else if (a=="-p" && i+1<argc) ports_spec=argv[++i];
        else if (a=="-m" && i+1<argc) threads=std::stoi(argv[++i]);
        else if (a=="-o" && i+1<argc) out_file=argv[++i];
        else if (a=="--syn") use_syn=true;
        else if (a=="--banner") use_banner=true;
    }

    if (target.empty()||ports_spec.empty()) { print_usage(argv[0]); return 1; }

    auto ip=resolve_target_to_ipv4(target);
    if (!ip) { std::cerr<<"[-] Cannot resolve target\n"; return 1; }
    auto ports=parse_ports(ports_spec);

    ScanMode mode=ScanMode::CONNECT;
#ifdef __linux__
    if (use_syn) mode=ScanMode::SYN;
#endif

    Scanner s(*ip, ports, threads, timeout_ms, mode, use_banner);
    s.run();
    s.save_json(out_file);
}
