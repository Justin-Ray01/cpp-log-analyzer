#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

struct Findings {
    long long total_lines = 0;

    // SSH failed
    long long ssh_failed_total = 0;
    std::unordered_map<std::string, long long> ssh_failed_by_ip;
    std::unordered_map<std::string, long long> ssh_failed_by_user;

    // SSH accepted (successful logins)
    long long ssh_accepted_total = 0;
    std::unordered_map<std::string, long long> ssh_accepted_by_ip;
    std::unordered_map<std::string, long long> ssh_accepted_by_user;

    // sudo auth failures
    long long sudo_authfail_total = 0;
    std::unordered_map<std::string, long long> sudo_authfail_by_user;
};

static inline std::string trim(std::string s) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

static inline bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static inline std::vector<std::pair<std::string, long long>>
topN(const std::unordered_map<std::string, long long>& m, std::size_t n) {
    std::vector<std::pair<std::string, long long>> v;
    v.reserve(m.size());
    for (const auto& kv : m) v.push_back(kv);

    std::sort(v.begin(), v.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second; 
    return a.first < b.first;                              
        });

    if (v.size() > n) v.resize(n);
    return v;
}

static std::vector<std::pair<std::string, long long>>
over_threshold(const std::unordered_map<std::string, long long>& m, long long threshold) {
    std::vector<std::pair<std::string, long long>> v;
    if (threshold <= 0) return v;

    for (const auto& kv : m) {
        if (kv.second >= threshold) v.push_back(kv);
    }

    std::sort(v.begin(), v.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second;
    return a.first < b.first;
        });
    return v;
}

// Minimal JSON escaper 
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;
        }
    }
    return out;
}

static std::optional<std::string> extract_ip_after_from(const std::string& line) {
    const std::string needle = " from ";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    auto end = line.find(' ', pos);
    if (end == std::string::npos) end = line.size();
    std::string ip = trim(line.substr(pos, end - pos));
    if (ip.empty()) return std::nullopt;
    return ip;
}

static std::optional<std::string> extract_user_after_phrase(const std::string& line, const std::string& phrase) {
    auto pos = line.find(phrase);
    if (pos == std::string::npos) return std::nullopt;
    pos += phrase.size();

    auto end = line.find(' ', pos);
    if (end == std::string::npos) return std::nullopt;

    std::string user = trim(line.substr(pos, end - pos));
    if (user.empty()) return std::nullopt;
    return user;
}

static std::optional<std::string> extract_ssh_failed_user(const std::string& line) {
    const std::string needle = "Failed password for ";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();

    const std::string invalid = "invalid user ";
    if (starts_with(line.substr(pos), invalid)) pos += invalid.size();

    auto end = line.find(' ', pos);
    if (end == std::string::npos) return std::nullopt;

    std::string user = trim(line.substr(pos, end - pos));
    if (user.empty()) return std::nullopt;
    return user;
}

static std::optional<std::string> extract_sudo_user(const std::string& line) {
    const std::string needle = "user=";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();

    auto end = line.find_first_of(" ;\r\n\t", pos);
    if (end == std::string::npos) end = line.size();

    std::string user = trim(line.substr(pos, end - pos));
    if (user.empty()) return std::nullopt;
    return user;
}

static void analyze_line(const std::string& line, Findings& f) {
    f.total_lines++;

    // SSH failed password
    if (line.find("sshd") != std::string::npos && line.find("Failed password for") != std::string::npos) {
        f.ssh_failed_total++;

        if (auto user = extract_ssh_failed_user(line)) f.ssh_failed_by_user[*user]++;
        else f.ssh_failed_by_user["(unknown)"]++;

        if (auto ip = extract_ip_after_from(line)) f.ssh_failed_by_ip[*ip]++;
        else f.ssh_failed_by_ip["(unknown)"]++;

        return;
    }

    // SSH accepted password (successful login)
    if (line.find("sshd") != std::string::npos && line.find("Accepted password for ") != std::string::npos) {
        f.ssh_accepted_total++;

        if (auto user = extract_user_after_phrase(line, "Accepted password for ")) f.ssh_accepted_by_user[*user]++;
        else f.ssh_accepted_by_user["(unknown)"]++;

        if (auto ip = extract_ip_after_from(line)) f.ssh_accepted_by_ip[*ip]++;
        else f.ssh_accepted_by_ip["(unknown)"]++;

        return;
    }

    // sudo authentication failure
    if (line.find("sudo") != std::string::npos && line.find("authentication failure") != std::string::npos) {
        f.sudo_authfail_total++;
        if (auto user = extract_sudo_user(line)) f.sudo_authfail_by_user[*user]++;
        else f.sudo_authfail_by_user["(unknown)"]++;
        return;
    }
}

static void print_table(std::ostream& os,
    const std::vector<std::pair<std::string, long long>>& rows,
    int leftWidth = 18) {
    if (rows.empty()) {
        os << "    (none)\n";
        return;
    }
    for (const auto& [k, v] : rows) {
        os << "    " << std::left << std::setw(leftWidth) << k
            << " " << std::right << v << "\n";
    }
}

static void print_pretty(std::ostream& os,
    const Findings& f,
    const std::string& input_path,
    std::size_t top,
    long long alert_threshold) {
    const int colW = 18;

    os << "C++ Log Analyzer\n";
    os << "File: " << input_path << "\n";
    os << "Lines processed: " << f.total_lines << "\n\n";

    os << "SSH Failed Logins: " << f.ssh_failed_total << "\n";
    os << "  Top IPs:\n";
    print_table(os, topN(f.ssh_failed_by_ip, top), colW);
    os << "  Top Usernames:\n";
    print_table(os, topN(f.ssh_failed_by_user, top), colW);
    os << "\n";

    os << "SSH Successful Logins: " << f.ssh_accepted_total << "\n";
    os << "  Top IPs:\n";
    print_table(os, topN(f.ssh_accepted_by_ip, top), colW);
    os << "  Top Usernames:\n";
    print_table(os, topN(f.ssh_accepted_by_user, top), colW);
    os << "\n";

    os << "Sudo Auth Failures: " << f.sudo_authfail_total << "\n";
    os << "  Top Usernames:\n";
    print_table(os, topN(f.sudo_authfail_by_user, top), colW);
    os << "\n";

    if (alert_threshold > 0) {
        auto sshAlerts = over_threshold(f.ssh_failed_by_ip, alert_threshold);
        auto sudoAlerts = over_threshold(f.sudo_authfail_by_user, alert_threshold);

        os << "ALERTS (threshold >= " << alert_threshold << ")\n";
        if (sshAlerts.empty() && sudoAlerts.empty()) {
            os << "  No alert thresholds exceeded.\n";
        }
        else {
            if (!sshAlerts.empty()) {
                os << "  SSH failed by IP:\n";
                print_table(os, sshAlerts, colW);
            }
            if (!sudoAlerts.empty()) {
                os << "  Sudo auth failures by user:\n";
                print_table(os, sudoAlerts, colW);
            }
        }
        os << "\n";
    }

    os << "Tip: use --json for machine-readable output.\n";
}

static void print_json(std::ostream& os,
    const Findings& f,
    std::size_t top,
    long long alert_threshold) {
    auto topFailIPs = topN(f.ssh_failed_by_ip, top);
    auto topFailUsers = topN(f.ssh_failed_by_user, top);

    auto topOkIPs = topN(f.ssh_accepted_by_ip, top);
    auto topOkUsers = topN(f.ssh_accepted_by_user, top);

    auto topSudoUsers = topN(f.sudo_authfail_by_user, top);

    auto sshAlerts = over_threshold(f.ssh_failed_by_ip, alert_threshold);
    auto sudoAlerts = over_threshold(f.sudo_authfail_by_user, alert_threshold);

    os << "{\n";
    os << "  \"total_lines\": " << f.total_lines << ",\n";
    os << "  \"ssh_failed_total\": " << f.ssh_failed_total << ",\n";
    os << "  \"ssh_accepted_total\": " << f.ssh_accepted_total << ",\n";
    os << "  \"sudo_authfail_total\": " << f.sudo_authfail_total << ",\n";

    os << "  \"top_ssh_failed_ips\": [\n";
    for (std::size_t i = 0; i < topFailIPs.size(); i++) {
        os << "    {\"ip\": \"" << json_escape(topFailIPs[i].first) << "\", \"count\": " << topFailIPs[i].second << "}";
        os << (i + 1 == topFailIPs.size() ? "\n" : ",\n");
    }
    os << "  ],\n";

    os << "  \"top_ssh_failed_usernames\": [\n";
    for (std::size_t i = 0; i < topFailUsers.size(); i++) {
        os << "    {\"username\": \"" << json_escape(topFailUsers[i].first) << "\", \"count\": " << topFailUsers[i].second << "}";
        os << (i + 1 == topFailUsers.size() ? "\n" : ",\n");
    }
    os << "  ],\n";

    os << "  \"top_ssh_success_ips\": [\n";
    for (std::size_t i = 0; i < topOkIPs.size(); i++) {
        os << "    {\"ip\": \"" << json_escape(topOkIPs[i].first) << "\", \"count\": " << topOkIPs[i].second << "}";
        os << (i + 1 == topOkIPs.size() ? "\n" : ",\n");
    }
    os << "  ],\n";

    os << "  \"top_ssh_success_usernames\": [\n";
    for (std::size_t i = 0; i < topOkUsers.size(); i++) {
        os << "    {\"username\": \"" << json_escape(topOkUsers[i].first) << "\", \"count\": " << topOkUsers[i].second << "}";
        os << (i + 1 == topOkUsers.size() ? "\n" : ",\n");
    }
    os << "  ],\n";

    os << "  \"top_sudo_usernames\": [\n";
    for (std::size_t i = 0; i < topSudoUsers.size(); i++) {
        os << "    {\"username\": \"" << json_escape(topSudoUsers[i].first) << "\", \"count\": " << topSudoUsers[i].second << "}";
        os << (i + 1 == topSudoUsers.size() ? "\n" : ",\n");
    }
    os << "  ],\n";

    os << "  \"alerts\": {\n";
    os << "    \"threshold\": " << alert_threshold << ",\n";

    os << "    \"ssh_failed_by_ip\": [\n";
    for (std::size_t i = 0; i < sshAlerts.size(); i++) {
        os << "      {\"ip\": \"" << json_escape(sshAlerts[i].first) << "\", \"count\": " << sshAlerts[i].second << "}";
        os << (i + 1 == sshAlerts.size() ? "\n" : ",\n");
    }
    os << "    ],\n";

    os << "    \"sudo_authfail_by_user\": [\n";
    for (std::size_t i = 0; i < sudoAlerts.size(); i++) {
        os << "      {\"username\": \"" << json_escape(sudoAlerts[i].first) << "\", \"count\": " << sudoAlerts[i].second << "}";
        os << (i + 1 == sudoAlerts.size() ? "\n" : ",\n");
    }
    os << "    ]\n";
    os << "  }\n";

    os << "}\n";
}

static void print_usage(const char* prog) {
    std::cout
        << "Usage:\n"
        << "  " << prog << " <path_to_log> [--json] [--pretty] [--top N] [--alert N] [--out PATH]\n\n"
        << "Notes:\n"
        << "  - Default output is pretty (human-readable).\n"
        << "  - Use --json for machine-readable output.\n\n"
        << "Examples:\n"
        << "  " << prog << " sample-logs/auth_sample.log\n"
        << "  " << prog << " sample-logs/auth_sample.log --alert 3\n"
        << "  " << prog << " sample-logs/auth_sample.log --json --alert 2\n"
        << "  " << prog << " sample-logs/auth_sample.log --json --alert 2 --out report.json\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string path;
    bool as_json = false;   
    std::size_t top = 10;
    long long alert_threshold = 0; // 0 = off
    std::string out_path;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--json") {
            as_json = true;
        }
        else if (arg == "--pretty") {
            as_json = false;
        }
        else if (arg == "--top") {
            if (i + 1 >= argc) { std::cerr << "Error: --top requires a number\n"; return 1; }
            try {
                long long n = std::stoll(argv[++i]);
                if (n <= 0) { std::cerr << "Error: --top must be > 0\n"; return 1; }
                top = static_cast<std::size_t>(n);
            }
            catch (...) {
                std::cerr << "Error: invalid number for --top\n"; return 1;
            }
        }
        else if (arg == "--alert") {
            if (i + 1 >= argc) { std::cerr << "Error: --alert requires a number\n"; return 1; }
            try {
                long long n = std::stoll(argv[++i]);
                if (n <= 0) { std::cerr << "Error: --alert must be > 0\n"; return 1; }
                alert_threshold = n;
            }
            catch (...) {
                std::cerr << "Error: invalid number for --alert\n"; return 1;
            }
        }
        else if (arg == "--out") {
            if (i + 1 >= argc) { std::cerr << "Error: --out requires a path\n"; return 1; }
            out_path = argv[++i];
        }
        else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
        else if (path.empty()) {
            path = arg;
        }
        else {
            std::cerr << "Error: unexpected argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (path.empty()) {
        std::cerr << "Error: missing log file path\n";
        print_usage(argv[0]);
        return 1;
    }

    std::ifstream in(path);
    if (!in) {
        std::cerr << "Error: could not open file: " << path << "\n";
        return 1;
    }

    Findings findings;
    std::string line;
    while (std::getline(in, line)) {
        analyze_line(line, findings);
    }

    // Choose output stream: console or file
    std::ofstream out_file;
    std::ostream* out = &std::cout;

    if (!out_path.empty()) {
        out_file.open(out_path, std::ios::out | std::ios::trunc);
        if (!out_file) {
            std::cerr << "Error: could not write to output file: " << out_path << "\n";
            return 1;
        }
        out = &out_file;
    }

    if (as_json) {
        print_json(*out, findings, top, alert_threshold);
    }
    else {
        print_pretty(*out, findings, path, top, alert_threshold);
    }

    return 0;
}
