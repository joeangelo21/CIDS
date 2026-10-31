// =============================================================================
// Sentinel v4.1 - Passive ARP / NDP / Gateway Monitor with Per-Host Telemetry
//
// Build (Compilation Hardening):
//   g++ -std=c++17 -O2 -Wall -Wextra -Wshadow -Wconversion -fstack-protector-strong
//       -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now sentinel.cpp -o sentinel -lpcap
//
// Test Build with Sanitizers:
//   g++ -std=c++17 -g -O1 -fsanitize=address,undefined sentinel.cpp -o sentinel_asan -lpcap
//
// Fuzzer Build (libFuzzer, requires Clang):
//   clang++ -std=c++17 -g -O1 -DSENTINEL_FUZZ -fsanitize=fuzzer,address,undefined
//       sentinel.cpp -o sentinel_fuzz -lpcap
//
// Usage:
//   sudo ./sentinel [-i iface] [-r pcap_file] [-g gw_ip] [-m gw_mac]... [-p pps] [-v]
//   ./sentinel -r capture.pcap [-g gw_ip] [-m gw_mac]... [-p pps] [-v]
// =============================================================================
#include <arpa/inet.h>
#include <grp.h>
#include <pcap.h>
#include <poll.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Mac = std::array<uint8_t, 6>;
using Addr = std::array<uint8_t, 16>; // IPv4 is stored as ::ffff:a.b.c.d

namespace cfg {
constexpr int SNAPLEN = 192; // Headers + ND options (RA with options fit safely)
constexpr int TIMEOUT_MS = 1000;
constexpr size_t MAX_HOSTS = 8192;
constexpr size_t MAX_COOLDOWN_KEYS = 4096;
constexpr size_t MAX_ROUTERS6 = 64;
constexpr auto HOST_IDLE_TTL = std::chrono::seconds(120);
constexpr auto TICK_EVERY = std::chrono::seconds(1);
constexpr auto ALERT_COOLDOWN = std::chrono::seconds(5);
constexpr auto RA_LEARN_WINDOW = std::chrono::seconds(60);
constexpr double DEFAULT_PPS_LIMIT = 2000.0;
constexpr double EWMA_ALPHA = 0.5;
constexpr unsigned MAX_LOG_LINES_PER_SEC = 100;
constexpr unsigned MAX_ALERTS_PER_SEC = 50;
// IPv4/ARP/IPv6 and any frame with VLAN/QinQ tags: parser handles up to 2 tags and strips the rest.
const char* const BPF_FILTER = "ip or arp or ip6 or vlan";
} // namespace cfg

// Runtime configuration (populated by main or the fuzzer)
struct Config {
    uint32_t gw4 = 0;             // IPv4 gateway (network order), 0 = disabled
    std::vector<Mac> gw_macs;     // Legitimate gateway MACs (-m); empty = auto-learn
    uint32_t local_net = 0;       // Local IPv4 network (network order)
    uint32_t local_mask = 0;      // 0 = do not filter by subnet
    double pps_limit = cfg::DEFAULT_PPS_LIMIT;
    bool verbose = false;
};

// ---------------------------------------------------------------- Utilities

struct AddrHash {
    size_t operator()(const Addr& a) const noexcept {
        uint64_t h = 1469598103934665603ULL; // FNV-1a
        for (uint8_t b : a) {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return static_cast<size_t>(h);
    }
};

static inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

static Mac to_mac(const uint8_t* p) {
    Mac m;
    std::memcpy(m.data(), p, 6);
    return m;
}

static Addr addr_from_v4(uint32_t s_addr_net) {
    Addr a{};
    a[10] = 0xff;
    a[11] = 0xff;
    std::memcpy(a.data() + 12, &s_addr_net, 4);
    return a;
}

static Addr addr_from_v6(const uint8_t* p) {
    Addr a;
    std::memcpy(a.data(), p, 16);
    return a;
}

static bool is_v4_mapped(const Addr& a) {
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return std::memcmp(a.data(), prefix, 12) == 0;
}

static std::string addr_str(const Addr& a) {
    char buf[INET6_ADDRSTRLEN];
    if (is_v4_mapped(a)) {
        if (!inet_ntop(AF_INET, a.data() + 12, buf, sizeof buf)) return "?";
    } else if (!inet_ntop(AF_INET6, a.data(), buf, sizeof buf)) {
        return "?";
    }
    return buf;
}

static std::string ip4_str(uint32_t s_addr_net) { return addr_str(addr_from_v4(s_addr_net)); }

static std::string mac_str(const Mac& m) {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

static bool parse_mac(const char* s, Mac& out) {
    unsigned v[6];
    int n = 0;
    if (std::sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%n", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &n) != 6 ||
        s[n] != '\0')
        return false;
    for (size_t i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(v[i]);
    return true;
}

constexpr uint8_t PROTO_ICMPV6 = 58;

static const char* proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        case PROTO_ICMPV6: return "ICMPv6";
        default:           return "OTHER";
    }
}

// Time is derived from the packet timestamp: PCAP replay remains deterministic
static TimePoint ts_to_tp(const timeval& tv) {
    return TimePoint(std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(tv.tv_sec) +
                                                                 std::chrono::microseconds(tv.tv_usec)));
}

static TimePoint wall_now() {
    return TimePoint(std::chrono::duration_cast<Clock::duration>(std::chrono::system_clock::now().time_since_epoch()));
}

// Key-based Cooldown: a noisy alert from one source does not silence others
class Cooldown {
public:
    bool ok(const std::string& key, TimePoint now) {
        auto it = last_.find(key);
        if (it != last_.end()) {
            if (now - it->second < cfg::ALERT_COOLDOWN) return false;
            it->second = now;
            return true;
        }
        if (last_.size() >= cfg::MAX_COOLDOWN_KEYS) purge(now);
        last_.emplace(key, now);
        return true;
    }

private:
    void purge(TimePoint now) {
        for (auto it = last_.begin(); it != last_.end();)
            it = (now - it->second >= cfg::ALERT_COOLDOWN) ? last_.erase(it) : std::next(it);
        if (last_.size() >= cfg::MAX_COOLDOWN_KEYS) last_.clear(); // Protection against key flood
    }
    std::unordered_map<std::string, TimePoint> last_;
};

// Line rate limiter per second (logs and alerts)
class RateLimiter {
public:
    RateLimiter(unsigned max_per_sec, const char* what) : max_(max_per_sec), what_(what) {}

    bool allow(TimePoint now) {
        if (now < window_ || now - window_ >= std::chrono::seconds(1)) {
            if (suppressed_) {
                std::cout << "[!] " << suppressed_ << " " << what_ << " (rate limited)\n";
                suppressed_ = 0;
            }
            window_ = now;
            count_ = 0;
        }
        if (count_ < max_) {
            ++count_;
            return true;
        }
        ++suppressed_;
        return false;
    }

private:
    unsigned max_;
    const char* what_;
    TimePoint window_{};
    unsigned count_ = 0;
    uint64_t suppressed_ = 0;
};

// ------------------------------------------------------------------- Telemetry

struct HostTelemetry {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    TimePoint last_seen{};
    unsigned window_packets = 0;
    double ewma_pps = 0.0;
    int trust_score = 100; // 100 = trusted; < 50 = flagged as anomalous
    bool flagged = false;
    std::list<Addr>::iterator lru_it;
};

class Monitor {
public:
    explicit Monitor(Config c) : cfg_(std::move(c)), gw_macs_(cfg_.gw_macs) {
        if (cfg_.gw4) gw_addr_ = addr_from_v4(cfg_.gw4);
    }

    void on_packet(const pcap_pkthdr* h, const u_char* d) {
        const TimePoint now = ts_to_tp(h->ts);
        ++seen_;
        tick(now);

        const size_t len = h->caplen;
        if (len < 14) {
            ++malformed_;
            return;
        }
        const Mac src_mac = to_mac(d + 6);
        size_t off = 14;
        uint16_t ethertype = rd16(d + 12);
        // Up to two tags (802.1Q / 802.1ad)
        for (int tag = 0; tag < 2 && (ethertype == 0x8100 || ethertype == 0x88a8); ++tag) {
            if (len < off + 4) {
                ++malformed_;
                return;
            }
            ethertype = rd16(d + off + 2);
            off += 4;
        }
        switch (ethertype) {
            case 0x0806: handle_arp(d + off, len - off, src_mac, now); break;
            case 0x0800: handle_ip4(h, d + off, len - off, src_mac, now); break;
            case 0x86dd: handle_ip6(h, d + off, len - off, src_mac, now); break;
            default: break;
        }
    }

    // Closes 1s windows for all hosts. Also called during idle periods.
    void tick(TimePoint now) {
        if (!ticked_ || now < last_tick_) {
            ticked_ = true;
            last_tick_ = now;
            return;
        }
        if (now - last_tick_ < cfg::TICK_EVERY) return;
        const double elapsed = std::chrono::duration<double>(now - last_tick_).count();
        last_tick_ = now;

        for (auto it = hosts_.begin(); it != hosts_.end();) {
            HostTelemetry& h = it->second;
            if (now - h.last_seen > cfg::HOST_IDLE_TTL) {
                lru_.erase(h.lru_it);
                it = hosts_.erase(it);
                continue;
            }
            const double pps = h.window_packets / elapsed;
            h.ewma_pps = cfg::EWMA_ALPHA * pps + (1.0 - cfg::EWMA_ALPHA) * h.ewma_pps;
            h.window_packets = 0;

            // Gateway aggregates traffic from all sources: excluded from rate heuristics
            const bool exempt = cfg_.gw4 && it->first == gw_addr_;
            const bool over = !exempt && h.ewma_pps > cfg_.pps_limit;
            h.trust_score = over ? std::max(0, h.trust_score - 20) : std::min(100, h.trust_score + 5);

            const bool now_flagged = h.trust_score < 50;
            if (now_flagged && !h.flagged)
                alert("rate:" + addr_str(it->first),
                      "Host " + addr_str(it->first) + " exhibiting abnormal packet rate (~" +
                          std::to_string(static_cast<long>(h.ewma_pps)) + " pkt/s, moving average), trust score " +
                          std::to_string(h.trust_score) + "%",
                      now);
            h.flagged = now_flagged;
            ++it;
        }
    }

    // SIGHUP: forgets learned gateway MAC (MACs passed via -m are preserved)
    void repin() {
        if (learned_) {
            gw_macs_.clear();
            learned_ = false;
            std::cout << "[*] SIGHUP: Gateway MAC will be re-learned\n";
        } else {
            std::cout << "[*] SIGHUP: Gateway MACs originated from -m and were preserved\n";
        }
        routers6_.clear();
        ra_learn_until_ = TimePoint{};
        ra_learning_ = false;
    }

    void print_summary() const {
        std::cout << "[*] Packets seen: " << seen_ << " | malformed: " << malformed_
                  << " | alerts: " << alerts_ << " | tracked hosts: " << hosts_.size()
                  << " | off-subnet (ignored): " << offnet_ << " | evicted due to full table: "
                  << evicted_ << '\n';
    }

    uint64_t alerts() const { return alerts_; }

private:
    // ------------------------------------------------------------------ IPv4
    void handle_ip4(const pcap_pkthdr* h, const uint8_t* p, size_t n, const Mac& src_mac, TimePoint now) {
        if (n < 20) {
            ++malformed_;
            return;
        }
        const unsigned version = p[0] >> 4;
        const unsigned ihl = (p[0] & 0x0Fu) * 4u;
        const unsigned tot_len = rd16(p + 2);
        if (version != 4 || ihl < 20 || ihl > n || tot_len < ihl) {
            ++malformed_;
            return;
        }
        const uint8_t proto = p[9];
        uint32_t saddr, daddr;
        std::memcpy(&saddr, p + 12, 4);
        std::memcpy(&daddr, p + 16, 4);

        if (cfg_.gw4 && saddr == cfg_.gw4) check_gateway_mac(src_mac, "IP", now);

        // Only track local subnet sources: external spoofed IPs will not exhaust table memory
        HostTelemetry* host = nullptr;
        if (cfg_.local_mask && (saddr & cfg_.local_mask) != (cfg_.local_net & cfg_.local_mask))
            ++offnet_;
        else
            host = track(addr_from_v4(saddr), h->len, now);

        const bool gw_event = cfg_.gw4 && (saddr == cfg_.gw4 || daddr == cfg_.gw4);
        if ((cfg_.verbose || gw_event) && log_rl_.allow(now)) {
            std::cout << (gw_event ? "[GATEWAY AUDIT]" : "[NORMAL]") << " [IP] " << ip4_str(saddr) << " -> "
                      << ip4_str(daddr) << " | Proto: " << proto_name(proto) << " | Len: " << h->len
                      << "B | Trust: ";
            print_trust(host);
        }
    }

    // ------------------------------------------------------------------ ARP
    void handle_arp(const uint8_t* p, size_t n, const Mac& eth_src, TimePoint now) {
        if (n < 28) {
            ++malformed_;
            return;
        }
        const unsigned hrd = rd16(p);
        const unsigned pro = rd16(p + 2);
        if (hrd != 1 || pro != 0x0800 || p[4] != 6 || p[5] != 4) return;

        const Mac sha = to_mac(p + 8);
        uint32_t spa;
        std::memcpy(&spa, p + 14, 4);

        // Can be legitimate with proxy ARP, network bridges, and VMs
        if (sha != eth_src)
            alert("arp-eth:" + mac_str(eth_src) + ":" + ip4_str(spa),
                  "Inconsistent ARP: Ethernet=" + mac_str(eth_src) + " ARP=" + mac_str(sha) + " for IP " +
                      ip4_str(spa),
                  now);

        if (cfg_.gw4 && spa == cfg_.gw4) check_gateway_mac(sha, "ARP", now);
    }

    void check_gateway_mac(const Mac& mac, const char* via, TimePoint now) {
        if (gw_macs_.empty()) {
            gw_macs_.push_back(mac);
            learned_ = true;
            std::cout << "[+] Gateway MAC pinned: " << mac_str(mac) << " (via " << via
                      << ", learned on first contact; use -m to pin beforehand)\n";
            return;
        }
        if (std::find(gw_macs_.begin(), gw_macs_.end(), mac) != gw_macs_.end()) return;

        std::string expected;
        for (const Mac& m : gw_macs_) expected += (expected.empty() ? "" : ",") + mac_str(m);
        alert(std::string("gwmac:") + mac_str(mac),
              std::string("Gateway MAC changed (via ") + via + "): expected " + expected + ", observed " +
                  mac_str(mac) + " - potential ARP spoofing / MITM attack",
              now);
    }

    // ------------------------------------------------------------------ IPv6 / NDP
    void handle_ip6(const pcap_pkthdr* h, const uint8_t* p, size_t n, const Mac& src_mac, TimePoint now) {
        if (n < 40 || (p[0] >> 4) != 6) {
            ++malformed_;
            return;
        }
        const uint8_t hop_limit = p[7];
        const Addr src = addr_from_v6(p + 8);
        const Addr dst = addr_from_v6(p + 24);

        // Traverse a few simple extension headers to find the final protocol
        uint8_t next = p[6];
        size_t off = 40;
        for (int i = 0; i < 3 && (next == 0 || next == 43 || next == 60); ++i) {
            if (n < off + 8) {
                ++malformed_;
                return;
            }
            const size_t ext_len = (static_cast<size_t>(p[off + 1]) + 1) * 8;
            next = p[off];
            off += ext_len;
        }
        if (off > n) {
            ++malformed_;
            return;
        }

        HostTelemetry* host = track(src, h->len, now);

        if (cfg_.verbose && log_rl_.allow(now)) {
            std::cout << "[NORMAL] [IP6] " << addr_str(src) << " -> " << addr_str(dst)
                      << " | Proto: " << proto_name(next) << " | Len: " << h->len << "B | Trust: ";
            print_trust(host);
        }

        if (next == PROTO_ICMPV6) handle_icmp6(p + off, n - off, hop_limit, src, src_mac, now);
    }

    // Search for a link-layer address option (type 1 = source, 2 = target) in ND messages
    static bool find_lladdr_option(const uint8_t* opts, size_t n, uint8_t type, Mac& out) {
        size_t off = 0;
        while (off + 2 <= n) {
            const size_t olen = static_cast<size_t>(opts[off + 1]) * 8;
            if (olen == 0 || off + olen > n) return false; // Invalid or truncated option
            if (opts[off] == type && olen >= 8) {
                out = to_mac(opts + off + 2);
                return true;
            }
            off += olen;
        }
        return false;
    }

    void handle_icmp6(const uint8_t* p, size_t n, uint8_t hop_limit, const Addr& src, const Mac& eth_src,
                      TimePoint now) {
        if (n < 4) return;
        const uint8_t type = p[0];
        if (type < 133 || type > 136) return; // RS, RA, NS, NA

        const std::string who = addr_str(src) + " (" + mac_str(eth_src) + ")";
        // RFC 4861: ND messages must arrive with Hop Limit 255 (proving they are on-link)
        if (hop_limit != 255)
            alert("nd-hop:" + addr_str(src),
                  "ND message (type " + std::to_string(type) + ") with hop limit " + std::to_string(hop_limit) +
                      " from " + who + " - message potentially forged off-link",
                  now);

        if (type == 134) { // Router Advertisement
            if (n < 16) {
                ++malformed_;
                return;
            }
            const unsigned lifetime = rd16(p + 6);
            Mac adv = eth_src;
            Mac opt;
            if (find_lladdr_option(p + 16, n - 16, 1, opt)) {
                if (opt != eth_src)
                    alert("ra-incons:" + mac_str(eth_src),
                          "Inconsistent RA: Ethernet=" + mac_str(eth_src) + " option=" + mac_str(opt) + " from " +
                              addr_str(src),
                          now);
                adv = opt;
            }
            if (lifetime > 0) check_router6(src, adv, now);
        } else if (type == 135 || type == 136) { // NS / NA
            if (n < 24) {
                ++malformed_;
                return;
            }
            const Addr target = addr_from_v6(p + 8);
            Mac opt;
            const bool has_opt = find_lladdr_option(p + 24, n - 24, type == 135 ? 1 : 2, opt);
            if (has_opt && opt != eth_src)
                alert("nd-eth:" + mac_str(eth_src) + ":" + addr_str(target),
                      std::string(type == 135 ? "NS" : "NA") + " inconsistent: Ethernet=" + mac_str(eth_src) +
                          " option=" + mac_str(opt) + " target " + addr_str(target),
                      now);
            // NA (or NS) claiming a known router is at a different MAC = NDP spoofing
            const Mac claimed = has_opt ? opt : eth_src;
            auto it = routers6_.find(type == 136 ? target : src);
            if (it != routers6_.end() && it->second != claimed)
                alert("ndp-spoof:" + addr_str(it->first) + ":" + mac_str(claimed),
                      "NDP spoofing: " + addr_str(it->first) + " (known router at " + mac_str(it->second) +
                          ") announced at " + mac_str(claimed),
                      now);
        }
    }

    // IPv6 routers are learned during an initial window; afterwards, any new router triggers an alert
    void check_router6(const Addr& router, const Mac& mac, TimePoint now) {
        if (!ra_learning_) {
            ra_learning_ = true;
            ra_learn_until_ = now + cfg::RA_LEARN_WINDOW;
        }
        auto it = routers6_.find(router);
        if (it == routers6_.end()) {
            if (now <= ra_learn_until_ && routers6_.size() < cfg::MAX_ROUTERS6) {
                routers6_.emplace(router, mac);
                std::cout << "[+] IPv6 Router learned: " << addr_str(router) << " at " << mac_str(mac) << '\n';
            } else {
                alert("rogue-ra:" + addr_str(router) + ":" + mac_str(mac),
                      "New IPv6 router advertising RA: " + addr_str(router) + " at " + mac_str(mac) +
                          " - potential Rogue RA / mitm6 attack",
                      now);
            }
        } else if (it->second != mac) {
            alert("ra-mac:" + addr_str(router) + ":" + mac_str(mac),
                  "IPv6 router " + addr_str(router) + " MAC changed: expected " + mac_str(it->second) +
                      ", observed " + mac_str(mac),
                  now);
        }
    }

    // ------------------------------------------------------------------ Host Table (LRU)
    HostTelemetry* track(const Addr& a, unsigned wire_len, TimePoint now) {
        auto it = hosts_.find(a);
        if (it == hosts_.end()) {
            if (hosts_.size() >= cfg::MAX_HOSTS) { // Evict the least recently used entry
                hosts_.erase(lru_.back());
                lru_.pop_back();
                ++evicted_;
            }
            lru_.push_front(a);
            it = hosts_.emplace(a, HostTelemetry{}).first;
            it->second.lru_it = lru_.begin();
        } else {
            lru_.splice(lru_.begin(), lru_, it->second.lru_it);
        }
        HostTelemetry& h = it->second;
        h.last_seen = now;
        ++h.packets;
        ++h.window_packets;
        h.bytes += wire_len;
        return &h;
    }

    static void print_trust(const HostTelemetry* host) {
        if (host)
            std::cout << host->trust_score << "%\n";
        else
            std::cout << "n/a\n";
    }

    void alert(const std::string& key, const std::string& msg, TimePoint now) {
        if (!cooldown_.ok(key, now) || !alert_rl_.allow(now)) return;
        ++alerts_;
        std::cout << "[ALERT] " << msg << std::endl;
    }

    Config cfg_;
    Addr gw_addr_{};
    std::vector<Mac> gw_macs_;
    bool learned_ = false;

    std::unordered_map<Addr, Mac, AddrHash> routers6_;
    bool ra_learning_ = false;
    TimePoint ra_learn_until_{};

    std::unordered_map<Addr, HostTelemetry, AddrHash> hosts_;
    std::list<Addr> lru_; // Most recent at the front

    Cooldown cooldown_;
    RateLimiter log_rl_{cfg::MAX_LOG_LINES_PER_SEC, "suppressed log lines"};
    RateLimiter alert_rl_{cfg::MAX_ALERTS_PER_SEC, "suppressed alerts"};

    TimePoint last_tick_{};
    bool ticked_ = false;
    uint64_t seen_ = 0, malformed_ = 0, offnet_ = 0, evicted_ = 0, alerts_ = 0;
};

// =============================================================================
#ifdef SENTINEL_FUZZ
// libFuzzer Harness: each input is a raw Ethernet frame
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static Monitor monitor([] {
        Config c;
        inet_pton(AF_INET, "192.168.0.1", &c.gw4);
        std::cout.setstate(std::ios::failbit);
        return c;
    }());
    static long sec = 1700000000;
    pcap_pkthdr h{};
    h.ts.tv_sec = sec++;
    h.caplen = static_cast<bpf_u_int32>(std::min<size_t>(size, cfg::SNAPLEN));
    h.len = static_cast<bpf_u_int32>(size);
    monitor.on_packet(&h, data);
    return 0;
}
#else
// ------------------------------------------------- Route / Gateway Discovery

struct Route {
    std::string iface;
    uint32_t gw = 0;
};

static Route default_route() {
    Route best;
    int best_metric = INT_MAX;
    std::ifstream f("/proc/net/route");
    std::string line;
    std::getline(f, line);
    while (std::getline(f, line)) {
        char iface[32];
        unsigned long dest, gw, mask;
        unsigned flags;
        int refcnt, use, metric;
        if (std::sscanf(line.c_str(), "%31s %lx %lx %x %d %d %d %lx", iface, &dest, &gw, &flags, &refcnt, &use,
                        &metric, &mask) != 8)
            continue;
        if (dest != 0 || mask != 0 || (flags & 0x3) != 0x3) continue;
        if (metric < best_metric) {
            best_metric = metric;
            best.iface = iface;
            best.gw = static_cast<uint32_t>(gw);
        }
    }
    return best;
}

static std::string first_usable_iface() {
    char err[PCAP_ERRBUF_SIZE];
    pcap_if_t* raw = nullptr;
    if (pcap_findalldevs(&raw, err) == -1) return {};
    std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> guard(raw, pcap_freealldevs);
    for (pcap_if_t* d = raw; d; d = d->next) {
        if (!d->name || !std::strcmp(d->name, "any")) continue;
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (!(d->flags & PCAP_IF_UP) || !(d->flags & PCAP_IF_RUNNING)) continue;
        return d->name;
    }
    return {};
}

// ------------------------------------------------------------------ Privileges

static bool parse_id(const char* s, unsigned long& out) {
    if (!s || !*s) return false;
    char* end = nullptr;
    errno = 0;
    out = std::strtoul(s, &end, 10);
    return errno == 0 && end && *end == '\0';
}

static bool drop_privileges() {
    if (geteuid() != 0) return true;

    unsigned long uid = 0, gid = 0;
    if (!(parse_id(std::getenv("SUDO_UID"), uid) && parse_id(std::getenv("SUDO_GID"), gid))) {
        const passwd* pw = getpwnam("nobody");
        if (!pw) return false;
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }
    if (uid == 0) return false;

    if (setgroups(0, nullptr) != 0) return false;
    if (setgid(static_cast<gid_t>(gid)) != 0) return false;
    if (setuid(static_cast<uid_t>(uid)) != 0) return false;
    if (setuid(0) == 0) return false; // Must not be able to regain root privileges
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    return true;
}

// ----------------------------------------------------------------- Signals / Main Loop

static pcap_t* g_handle = nullptr;
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_failed = 0;
static volatile sig_atomic_t g_repin = 0;

static void on_signal(int) {
    g_stop = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

static void on_sighup(int) { g_repin = 1; }

static void packet_handler(u_char* user, const pcap_pkthdr* h, const u_char* d) {
    try {
        reinterpret_cast<Monitor*>(user)->on_packet(h, d);
    } catch (...) {
        g_failed = 1;
        pcap_breakloop(g_handle);
    }
}

static int usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [-i interface | -r pcap_file] [-g gateway_ip] [-m gateway_mac]...\n"
              << "          [-p pps_limit] [-v]\n"
              << "  -m can be repeated (VRRP, mesh, dual-WAN). Without -m, the MAC is learned on first contact.\n"
              << "  SIGHUP re-learns the gateway MAC.\n";
    return 2;
}

int main(int argc, char** argv) {
    std::string iface, pcap_file;
    Config conf;
    bool gw_forced = false;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:g:m:p:vh")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'r': pcap_file = optarg; break;
            case 'g': {
                in_addr a{};
                if (inet_pton(AF_INET, optarg, &a) != 1) {
                    std::cerr << "[-] Invalid gateway IP: " << optarg << '\n';
                    return 2;
                }
                conf.gw4 = a.s_addr;
                gw_forced = true;
                break;
            }
            case 'm': {
                Mac m;
                if (!parse_mac(optarg, m)) {
                    std::cerr << "[-] Invalid MAC address: " << optarg << " (expected aa:bb:cc:dd:ee:ff)\n";
                    return 2;
                }
                conf.gw_macs.push_back(m);
                break;
            }
            case 'p': {
                char* end = nullptr;
                const double v = std::strtod(optarg, &end);
                if (!end || *end != '\0' || !(v > 0)) {
                    std::cerr << "[-] Invalid PPS limit: " << optarg << '\n';
                    return 2;
                }
                conf.pps_limit = v;
                break;
            }
            case 'v': conf.verbose = true; break;
            default: return usage(argv[0]);
        }
    }
    if (!iface.empty() && !pcap_file.empty()) {
        std::cerr << "[-] Use either -i or -r, not both.\n";
        return 2;
    }

    const bool offline = !pcap_file.empty();
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(nullptr, pcap_close);

    if (offline) {
        handle.reset(pcap_open_offline(pcap_file.c_str(), errbuf));
        if (!handle) {
            std::cerr << "[-] Error opening " << pcap_file << ": " << errbuf << '\n';
            return 1;
        }
        std::cout << "[*] Initializing Sentinel v4.1 | replay: " << pcap_file << " | gateway: "
                  << (conf.gw4 ? ip4_str(conf.gw4) : std::string("not specified (use -g)")) << '\n';
    } else {
        const Route route = default_route();
        if (iface.empty()) iface = route.iface;
        if (iface.empty()) iface = first_usable_iface();
        if (iface.empty()) {
            std::cerr << "[-] No usable network interface found. Use -i.\n";
            return 1;
        }
        if (!gw_forced && route.iface == iface) conf.gw4 = route.gw;

        bpf_u_int32 net = 0, mask = 0;
        if (pcap_lookupnet(iface.c_str(), &net, &mask, errbuf) == 0 && mask != 0) {
            conf.local_net = net;
            conf.local_mask = mask;
        } else {
            std::cerr << "[!] Subnet for " << iface << " unknown; running without subnet filtering.\n";
        }

        std::cout << "[*] Initializing Sentinel v4.1 | interface: " << iface << " | gateway: "
                  << (conf.gw4 ? ip4_str(conf.gw4) : std::string("not detected (audit disabled)")) << '\n';

        handle.reset(pcap_open_live(iface.c_str(), cfg::SNAPLEN, 1, cfg::TIMEOUT_MS, errbuf));
        if (!handle) {
            std::cerr << "[-] Error opening " << iface << ": " << errbuf << '\n';
            return 1;
        }
        // Ignore outbound traffic generated by the host itself
        if (pcap_setdirection(handle.get(), PCAP_D_IN) != 0)
            std::cerr << "[!] Could not restrict to ingress traffic only; local generated traffic will be counted.\n";
    }

    if (pcap_datalink(handle.get()) != DLT_EN10MB) {
        std::cerr << "[-] Unsupported link-layer type (Ethernet expected).\n";
        return 1;
    }

    bpf_program fp{};
    if (pcap_compile(handle.get(), &fp, cfg::BPF_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[-] Failed to compile BPF filter: " << pcap_geterr(handle.get()) << '\n';
        return 1;
    }
    const int set_rc = pcap_setfilter(handle.get(), &fp);
    pcap_freecode(&fp);
    if (set_rc == -1) {
        std::cerr << "[-] Failed to apply BPF filter: " << pcap_geterr(handle.get()) << '\n';
        return 1;
    }

    // All tasks requiring root privileges are complete (opening capture handle, applying BPF filter)
    if (!drop_privileges()) {
        std::cerr << "[-] Failed to drop privileges; aborting for safety.\n";
        return 1;
    }

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    struct sigaction sh{};
    sh.sa_handler = on_sighup;
    sigemptyset(&sh.sa_mask);
    sigaction(SIGHUP, &sh, nullptr);

    Monitor monitor(conf);
    g_handle = handle.get();
    std::cout << "[+] Audit started. Press Ctrl+C to terminate.\n\n";

    // Live capture: non-blocking mode + poll(). libpcap timeout on Linux only triggers upon
    // packet arrival; without poll(), SIGHUP and idle rate window expiration would stall silently.
    int fd = -1;
    if (!offline) {
        if (pcap_setnonblock(handle.get(), 1, errbuf) != 0 || (fd = pcap_get_selectable_fd(handle.get())) < 0) {
            fd = -1;
            std::cerr << "[!] Non-blocking capture unavailable; SIGHUP and idle ticks will only run upon packet traffic.\n";
        }
    }

    int rc = 0;
    bool poll_failed = false;
    while (!g_stop) {
        if (g_repin) {
            g_repin = 0;
            monitor.repin();
        }
        if (fd >= 0) {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;
            const int pr = poll(&pfd, 1, cfg::TIMEOUT_MS);
            if (pr < 0) {
                if (errno == EINTR) continue; // Signal received: loop back to handle SIGHUP / g_stop
                std::cerr << "[-] Error in poll(): " << std::strerror(errno) << '\n';
                poll_failed = true;
                break;
            }
            if (pr == 0) { // Idle timeout: continue closing rate windows
                monitor.tick(wall_now());
                continue;
            }
        }
        rc = pcap_dispatch(handle.get(), 256, packet_handler, reinterpret_cast<u_char*>(&monitor));
        if (rc == PCAP_ERROR_BREAK) {
            rc = 0;
            break;
        }
        if (rc == PCAP_ERROR) break;
        if (g_failed) break;
        if (rc == 0 && offline) break; // End of PCAP file
    }

    int exit_code = poll_failed ? 1 : 0;
    if (rc == PCAP_ERROR) {
        std::cerr << "[-] Capture error: " << pcap_geterr(handle.get()) << '\n';
        exit_code = 1;
    }
    if (g_failed) {
        std::cerr << "[-] Internal error processing packet (memory corruption?).\n";
        exit_code = 1;
    }

    if (!offline) {
        pcap_stat st{};
        if (pcap_stats(handle.get(), &st) == 0)
            std::cout << "\n[*] Kernel stats: received=" << st.ps_recv << " dropped=" << st.ps_drop << '\n';
    }
    monitor.print_summary();

    g_handle = nullptr;
    return exit_code;
}
#endif // SENTINEL_FUZZ
