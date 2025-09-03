#include "json_writer.hpp"
#include <fstream>
#include <sstream>

namespace JsonWriter {

    std::string escape(const std::string& str) {
        std::ostringstream oss;
        for (char c : str) {
            switch (c) {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;
                default: oss << c; break;
            }
        }
        return oss.str();
    }

    std::string to_json(const std::string& target, const std::vector<ScanResult>& results) {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"target\": \"" << escape(target) << "\",\n";
        oss << "  \"results\": [\n";

        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            oss << "    {\n";
            oss << "      \"port\": " << r.port << ",\n";
            oss << "      \"open\": " << (r.open ? "true" : "false") << ",\n";
            oss << "      \"banner\": \"" << escape(r.banner) << "\"\n";
            oss << "    }";
            if (i + 1 < results.size()) oss << ",";
            oss << "\n";
        }

        oss << "  ]\n";
        oss << "}\n";
        return oss.str();
    }

    bool save_to_file(const std::string& filename, const std::string& json_data) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        file << json_data;
        return true;
    }

}
