
//  Run:
// sudo ./(output name) eth0 192.168.1.10 192.168.1.20


#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std;


static inline uint64_t now_millis() {
    using namespace chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static string ipv4_to_string(uint32_t addr_network_order) {
    struct in_addr a;
    a.s_addr = addr_network_order;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return string(buf);
}

static string ipv6_to_string(const struct in6_addr &addr) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return string(buf);
}

static bool is_valid_ipv4(const string &ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

static bool is_valid_ipv6(const string &ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) == 1;
}

// packets

struct Packet {
    uint64_t id;
    uint64_t timestamp_ms;
    vector<uint8_t> raw;

    // parsed metadata
    bool has_ipv4;
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    bool has_ipv6;
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
    bool has_tcp;
    bool has_udp;
    uint16_t src_port;
    uint16_t dst_port;
    int replay_attempts;

    Packet() {
        id = 0;
        timestamp_ms = 0;
        raw.clear();
        has_ipv4 = has_ipv6 = has_tcp = has_udp = false;
        src_ipv4 = dst_ipv4 = 0;
        memset(&src_ipv6, 0, sizeof(src_ipv6));
        memset(&dst_ipv6, 0, sizeof(dst_ipv6));
        src_port = dst_port = 0;
        replay_attempts = 0;
    }
};

// packet queue
template<typename T>
class PacketQueue {
private:
    struct Node {
        T data;
        Node *next;
        Node(const T &d): data(d), next(nullptr) {}
    };
    Node *head;
    Node *tail;
    size_t sz;
    size_t max_size;
    std::mutex m;

public:
    PacketQueue(size_t max_sz = 10000) 
        : head(nullptr), tail(nullptr), sz(0), max_size(max_sz) {}

    ~PacketQueue() {
        clear();
    }

    bool push(const T &item) {
        std::lock_guard<std::mutex> guard(m);
        if (sz >= max_size) return false;
        Node *n = new Node(item);
        if (!tail) {
            head = tail = n;
        } else {
            tail->next = n;
            tail = n;
        }
        ++sz;
        return true;
    }

    bool pop(T &out) {
        std::lock_guard<std::mutex> guard(m);
        if (!head) return false;
        Node *n = head;
        out = n->data;
        head = head->next;
        if (!head) tail = nullptr;
        delete n;
        --sz;
        return true;
    }

    vector<T> snapshot(size_t limit = 100) {
        vector<T> out;
        std::lock_guard<std::mutex> guard(m);
        Node *cur = head;
        while (cur && out.size() < limit) {
            out.push_back(cur->data);
            cur = cur->next;
        }
        return out;
    }

    size_t size() {
        std::lock_guard<std::mutex> guard(m);
        return sz;
    }

    void clear() {
        std::lock_guard<std::mutex> guard(m);
        while (head) {
            Node *n = head;
            head = head->next;
            delete n;
        }
        tail = nullptr;
        sz = 0;
    }
};

// stacks

template<typename T>
class SimpleStack {
private:
    struct Node {
        T value;
        Node *next;
        Node(T v): value(v), next(nullptr) {}
    };
    Node *topNode;
    size_t sz;

public:
    SimpleStack(): topNode(nullptr), sz(0) {}
    
    ~SimpleStack() {
        while (topNode) pop();
    }

    void push(T v) {
        Node *n = new Node(v);
        n->next = topNode;
        topNode = n;
        ++sz;
    }

    bool pop() {
        if (!topNode) return false;
        Node *n = topNode;
        topNode = topNode->next;
        delete n;
        --sz;
        return true;
    }

    T top() const {
        if (!topNode) throw runtime_error("Stack empty");
        return topNode->value;
    }

    bool empty() const {
        return topNode == nullptr;
    }

    size_t size() const {
        return sz;
    }
};

// different layers

enum LayerType {
    LAYER_ETHERNET,
    LAYER_IPV4,
    LAYER_IPV6,
    LAYER_TCP,
    LAYER_UDP,
    LAYER_UNKNOWN
};

// for disecting

class Dissector {
public:
    static bool dissect(Packet &p) {
        p.has_ipv4 = p.has_ipv6 = p.has_tcp = p.has_udp = false;
        p.src_ipv4 = p.dst_ipv4 = 0;
        memset(&p.src_ipv6, 0, sizeof(p.src_ipv6));
        memset(&p.dst_ipv6, 0, sizeof(p.dst_ipv6));
        p.src_port = p.dst_port = 0;

        if (p.raw.size() < 14) return false;

        SimpleStack<LayerType> st;
        st.push(LAYER_ETHERNET);
        size_t offset = 0;

        while (!st.empty()) {
            LayerType cur = st.top();
            if (cur == LAYER_ETHERNET) {
                if (p.raw.size() - offset < 14) {
                    st.pop();
                    break;
                }
                uint16_t ethertype = (uint16_t)((p.raw[offset + 12] << 8) | p.raw[offset + 13]);
                offset += 14;
                st.pop();

                if (ethertype == 0x0800) {
                    st.push(LAYER_IPV4);
                } else if (ethertype == 0x86DD) {
                    st.push(LAYER_IPV6);
                } else {
                    st.push(LAYER_UNKNOWN);
                }
            } else if (cur == LAYER_IPV4) {
                if (p.raw.size() - offset < 20) { st.pop(); break; }
                uint8_t ver_ihl = p.raw[offset];
                uint8_t ver = ver_ihl >> 4;
                if (ver != 4) { st.pop(); break; }
                uint8_t ihl = ver_ihl & 0x0F;
                uint8_t proto = p.raw[offset + 9];
                
                uint32_t src = (uint32_t)((p.raw[offset + 12] << 24) | 
                                         (p.raw[offset + 13] << 16) | 
                                         (p.raw[offset + 14] << 8) | 
                                          p.raw[offset + 15]);
                uint32_t dst = (uint32_t)((p.raw[offset + 16] << 24) | 
                                         (p.raw[offset + 17] << 16) | 
                                         (p.raw[offset + 18] << 8) | 
                                          p.raw[offset + 19]);
                
                p.has_ipv4 = true;
                p.src_ipv4 = htonl(src);
                p.dst_ipv4 = htonl(dst);
                offset += ihl * 4;
                st.pop();

                if (proto == IPPROTO_TCP) st.push(LAYER_TCP);
                else if (proto == IPPROTO_UDP) st.push(LAYER_UDP);
                else st.push(LAYER_UNKNOWN);
            } else if (cur == LAYER_IPV6) {
                if (p.raw.size() - offset < 40) { st.pop(); break; }
                memcpy(&p.src_ipv6, &p.raw[offset + 8], 16);
                memcpy(&p.dst_ipv6, &p.raw[offset + 24], 16);
                p.has_ipv6 = true;
                uint8_t next_hdr = p.raw[offset + 6];
                offset += 40;
                st.pop();

                if (next_hdr == IPPROTO_TCP) st.push(LAYER_TCP);
                else if (next_hdr == IPPROTO_UDP) st.push(LAYER_UDP);
                else st.push(LAYER_UNKNOWN);
            } else if (cur == LAYER_TCP) {
                if (p.raw.size() - offset < 20) { st.pop(); break; }
                uint16_t sport = (uint16_t)((p.raw[offset] << 8) | p.raw[offset + 1]);
                uint16_t dport = (uint16_t)((p.raw[offset + 2] << 8) | p.raw[offset + 3]);
                p.has_tcp = true;
                p.src_port = sport;
                p.dst_port = dport;
                st.pop();
            } else if (cur == LAYER_UDP) {
                if (p.raw.size() - offset < 8) { st.pop(); break; }
                uint16_t sport = (uint16_t)((p.raw[offset] << 8) | p.raw[offset + 1]);
                uint16_t dport = (uint16_t)((p.raw[offset + 2] << 8) | p.raw[offset + 3]);
                p.has_udp = true;
                p.src_port = sport;
                p.dst_port = dport;
                st.pop();
            } else {
                st.pop();
            }
        }
        return true;
    }

    static void show_layers(const Packet &p) {
        cout << "\n===== Packet ID: " << p.id << " | Timestamp: " << p.timestamp_ms << " ms =====\n";
        cout << " Layers: Ethernet";
        if (p.has_ipv4) cout << " -> IPv4";
        if (p.has_ipv6) cout << " -> IPv6";
        if (p.has_tcp) cout << " -> TCP";
        if (p.has_udp) cout << " -> UDP";
        cout << "\n";
        
        if (p.has_ipv4) {
            cout << " IPv4 Source:      " << ipv4_to_string(p.src_ipv4) << "\n";
            cout << " IPv4 Destination: " << ipv4_to_string(p.dst_ipv4) << "\n";
        }
        if (p.has_ipv6) {
            cout << " IPv6 Source:      " << ipv6_to_string(p.src_ipv6) << "\n";
            cout << " IPv6 Destination: " << ipv6_to_string(p.dst_ipv6) << "\n";
        }
        if (p.has_tcp) {
            cout << " TCP Ports:        " << p.src_port << " -> " << p.dst_port << "\n";
        }
        if (p.has_udp) {
            cout << " UDP Ports:        " << p.src_port << " -> " << p.dst_port << "\n";
        }
        cout << " Raw size:         " << p.raw.size() << " bytes\n";
        cout << "=================================================================\n";
    }
};

// for capturing

class CaptureManager {
private:
    string iface;
    int fd;
    int ifindex;
    PacketQueue<Packet> &capture_q;
    atomic<bool> running;
    atomic<uint64_t> next_id;
    atomic<size_t> oversized_count;
    size_t oversized_threshold;
    atomic<uint64_t> &total_captured_ref;

public:
    CaptureManager(PacketQueue<Packet> &q, const string &ifname, 
                   atomic<uint64_t> &tc, size_t oversize_thresh = 10)
    : iface(ifname), fd(-1), ifindex(0), capture_q(q), running(false),
      next_id(1), oversized_count(0), oversized_threshold(oversize_thresh),
      total_captured_ref(tc) {}

    bool open_socket() {
        fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) {
            perror("socket(AF_PACKET)");
            return false;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
            perror("SIOCGIFINDEX");
            close(fd);
            fd = -1;
            return false;
        }
        ifindex = ifr.ifr_ifindex;

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
            perror("bind(AF_PACKET)");
            close(fd);
            fd = -1;
            return false;
        }
        return true;
    }

    void start() {
        running = true;
        thread t([this]() { this->run(); });
        t.detach();
    }

    void stop() {
        running = false;
        if (fd >= 0) { 
            shutdown(fd, SHUT_RDWR);
            close(fd); 
            fd = -1; 
        }
    }

    void run() {
        if (fd < 0) {
            if (!open_socket()) {
                cerr << "[Capture] Failed to open socket on interface " << iface << "\n";
                running = false;
                return;
            }
        }

        cout << "[Capture] Started on interface " << iface << "\n";
        const size_t BUF_MAX = 65536;
        vector<uint8_t> buf(BUF_MAX);

        while (running) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            struct timeval tv;
            tv.tv_sec = 1; 
            tv.tv_usec = 0;

            int ret = select(fd+1, &fds, NULL, NULL, &tv);
            if (ret < 0) {
                if (errno == EINTR) continue;
                if (!running) break;
                perror("[Capture] select");
                break;
            } else if (ret == 0) {
                continue;
            }

            ssize_t len = recvfrom(fd, buf.data(), (size_t)BUF_MAX, 0, NULL, NULL);
            if (len < 0) {
                if (errno == EINTR) continue;
                if (!running) break;
                perror("[Capture] recvfrom");
                continue;
            }

            // Check oversized BEFORE incrementing counter
            if ((size_t)len > 1500) {
                size_t current = oversized_count.load();
                if (current >= oversized_threshold) {
                    cout << "[Capture] Skipping oversized packet (" << len 
                         << " bytes) - threshold exceeded\n";
                    continue;
                }
                oversized_count++;
                cout << "[Capture] Warning: Oversized packet " << len 
                     << " bytes (count: " << oversized_count.load() << ")\n";
            }

            Packet p;
            p.id = next_id++;
            p.timestamp_ms = now_millis();
            p.raw.assign(buf.begin(), buf.begin() + len);
            p.replay_attempts = 0;

            if (!capture_q.push(p)) {
                cerr << "[Capture] Queue full; dropping packet id=" << p.id << "\n";
            } else {
                cout << "[Capture] Packet #" << p.id << " captured (" << len << " bytes)\n";
                total_captured_ref++;
            }
        }
        cout << "[Capture] Thread exiting\n";
    }
};
// for filtering

class FilterManager {
private:
    string filter_src_ip;
    string filter_dst_ip;
    PacketQueue<Packet> &input_q;
    PacketQueue<Packet> &output_q;
    atomic<bool> running;

public:
    FilterManager(PacketQueue<Packet> &in_q, PacketQueue<Packet> &out_q, 
                  const string &src, const string &dst)
    : filter_src_ip(src), filter_dst_ip(dst), input_q(in_q), 
      output_q(out_q), running(false) {}

    void start() {
        running = true;
        thread t([this]() { this->run(); });
        t.detach();
    }

    void stop() {
        running = false;
    }

    bool matches_filter(const Packet &p) {
        if (p.has_ipv4) {
            string src = ipv4_to_string(p.src_ipv4);
            string dst = ipv4_to_string(p.dst_ipv4);
            return (src == filter_src_ip && dst == filter_dst_ip);
        }
        if (p.has_ipv6) {
            string src = ipv6_to_string(p.src_ipv6);
            string dst = ipv6_to_string(p.dst_ipv6);
            return (src == filter_src_ip && dst == filter_dst_ip);
        }
        return false;
    }

    void run() {
        cout << "[Filter] Started with criteria: " << filter_src_ip 
             << " -> " << filter_dst_ip << "\n";
        
        while (running) {
            Packet p;
            if (input_q.pop(p)) {
                // Dissect first
                Dissector::dissect(p);
                
                // Show layers
                Dissector::show_layers(p);
                
                // Check filter
                if (matches_filter(p)) {
                    double delay_ms = ((double)p.raw.size()) / 1000.0;
                    cout << "[Filter] *** MATCH *** Packet #" << p.id << " matches filter\n";
                    cout << "[Filter] Estimated delay: " << delay_ms << " ms\n";
                    
                    if (!output_q.push(p)) {
                        cerr << "[Filter] Replay queue full for packet #" << p.id << "\n";
                    }
                }
            } else {
                this_thread::sleep_for(chrono::milliseconds(10));
            }
        }
        cout << "[Filter] Thread exiting\n";
    }
};

// replaying

class ReplayManager {
private:
    string iface;
    int fd;
    int ifindex;
    PacketQueue<Packet> &replay_q;
    PacketQueue<Packet> &backup_q;
    atomic<bool> running;
    atomic<uint64_t> &total_replayed_ref;

public:
    ReplayManager(PacketQueue<Packet> &replay_q_, PacketQueue<Packet> &backup_q_, 
                  const string &iface_, atomic<uint64_t> &tr)
    : iface(iface_), fd(-1), ifindex(0), replay_q(replay_q_), 
      backup_q(backup_q_), running(false), total_replayed_ref(tr) {}

    bool open_socket() {
        fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) {
            perror("[Replay] socket");
            return false;
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
            perror("[Replay] SIOCGIFINDEX");
            close(fd);
            fd = -1;
            return false;
        }
        ifindex = ifr.ifr_ifindex;
        return true;
    }

    void start() {
        running = true;
        thread t([this]() { this->run(); });
        t.detach();
    }

    void stop() {
        running = false;
        if (fd >= 0) { 
            close(fd); 
            fd = -1; 
        }
    }

    void run() {
        if (!open_socket()) {
            cerr << "[Replay] Failed to open socket\n";
            running = false;
            return;
        }

        cout << "[Replay] Started on interface " << iface << "\n";

        while (running) {
            Packet p;
            if (replay_q.pop(p)) {
                // Prepare sockaddr_ll for sending
                struct sockaddr_ll sll;
                memset(&sll, 0, sizeof(sll));
                sll.sll_family = AF_PACKET;
                sll.sll_ifindex = ifindex;
                sll.sll_halen = ETH_ALEN;
                sll.sll_protocol = htons(ETH_P_ALL);
                
                // Extract destination MAC from Ethernet header
                if (p.raw.size() >= 14) {
                    memcpy(sll.sll_addr, p.raw.data(), 6);
                }

                // Calculate delay and sleep
                double delay_ms = ((double)p.raw.size()) / 1000.0;
                if (delay_ms > 0.1) {
                    this_thread::sleep_for(chrono::milliseconds((int)delay_ms));
                }

                // Attempt replay with retries (up to 2 retries = 3 total attempts)
                bool success = false;
                const int MAX_ATTEMPTS = 3; // Initial + 2 retries
                
                for (int attempt = 0; attempt < MAX_ATTEMPTS && !success; ++attempt) {
                    ssize_t sent = sendto(fd, p.raw.data(), p.raw.size(), 0,
                                         (struct sockaddr*)&sll, sizeof(sll));
                    if (sent == (ssize_t)p.raw.size()) {
                        cout << "[Replay] Packet #" << p.id << " replayed successfully"
                             << " (attempt " << (attempt + 1) << "/" << MAX_ATTEMPTS << ")\n";
                        success = true;
                        total_replayed_ref++;
                    } else {
                        cerr << "[Replay] Packet #" << p.id << " send failed"
                             << " (attempt " << (attempt + 1) << "/" << MAX_ATTEMPTS 
                             << ", errno=" << errno << ")\n";
                        p.replay_attempts++;
                        if (attempt < MAX_ATTEMPTS - 1) {
                            this_thread::sleep_for(chrono::milliseconds(100));
                        }
                    }
                }

                if (!success) {
                    cout << "[Replay] Moving packet #" << p.id 
                         << " to backup queue after " << MAX_ATTEMPTS << " failed attempts\n";
                    if (!backup_q.push(p)) {
                        cerr << "[Replay] Backup queue full; packet #" << p.id << " lost\n";
                    }
                }
            } else {
                this_thread::sleep_for(chrono::milliseconds(10));
            }
        }
        cout << "[Replay] Thread exiting\n";
    }
};

// backing up packets

class BackupManager {
private:
    PacketQueue<Packet> &backup_q;
    PacketQueue<Packet> &replay_q;
    atomic<bool> running;

public:
    BackupManager(PacketQueue<Packet> &bq, PacketQueue<Packet> &rq)
    : backup_q(bq), replay_q(rq), running(false) {}

    void start() {
        running = true;
        thread t([this]() { this->run(); });
        t.detach();
    }

    void stop() {
        running = false;
    }

    void run() {
        cout << "[Backup] Thread started\n";
        
        while (running) {
            size_t count = backup_q.size();
            if (count > 0) {
                cout << "[Backup] Queue status: " << count << " packets awaiting recovery\n";
                
                // Optional: Retry logic - move some packets back to replay queue
                Packet p;
                if (backup_q.pop(p)) {
                    if (p.replay_attempts < 5) { // Allow more retries from backup
                        cout << "[Backup] Requeuing packet #" << p.id 
                             << " for retry (attempts: " << p.replay_attempts << ")\n";
                        replay_q.push(p);
                    } else {
                        cout << "[Backup] Packet #" << p.id 
                             << " permanently failed (too many attempts)\n";
                        backup_q.push(p); // Put back in backup
                    }
                }
            }
            this_thread::sleep_for(chrono::seconds(5));
        }
        cout << "[Backup] Thread exiting\n";
    }
};

// displaying

class DisplayManager {
private:
    PacketQueue<Packet> &capture_q;
    PacketQueue<Packet> &replay_q;
    PacketQueue<Packet> &backup_q;
    atomic<bool> running;
    atomic<uint64_t> &total_captured;
    atomic<uint64_t> &total_replayed;

public:
    DisplayManager(PacketQueue<Packet> &cq, PacketQueue<Packet> &rq, 
                   PacketQueue<Packet> &bq, atomic<uint64_t> &tc, 
                   atomic<uint64_t> &tr)
    : capture_q(cq), replay_q(rq), backup_q(bq), running(false),
      total_captured(tc), total_replayed(tr) {}

    void start() {
        running = true;
        thread t([this]() { this->run(); });
        t.detach();
    }

    void stop() {
        running = false;
    }

    void run() {
        cout << "[Display] Thread started\n";
        
        while (running) {
            cout << "\n";
            cout << "============ NETWORK MONITOR STATUS ============\n";
            cout << " Total Captured:    " << total_captured.load() << "\n";
            cout << " Total Replayed:    " << total_replayed.load() << "\n";
            cout << " Capture Queue:     " << capture_q.size() << " packets\n";
            cout << " Replay Queue:      " << replay_q.size() << " packets\n";
            cout << " Backup Queue:      " << backup_q.size() << " packets\n";
            cout << "================================================\n";
            
            this_thread::sleep_for(chrono::seconds(10));
        }
        cout << "[Display] Thread exiting\n";
    }
};


atomic<uint64_t> total_captured(0);
atomic<uint64_t> total_replayed(0);
atomic<bool> global_running(true);


void signal_handler(int signum) {
    cout << "\n[Main] Caught signal " << signum << ", shutting down...\n";
    global_running = false;
}

// MAIN FUNCTION
int main(int argc, char *argv[]) {
    // Parse command line arguments
    string iface = "wlan0"; // default interface
    string filter_src = "";
    string filter_dst = "";

    if (argc >= 2) {
        iface = argv[1];
    }
    if (argc >= 4) {
        filter_src = argv[2];
        filter_dst = argv[3];
        
        // Validate filter IPs
        if (!is_valid_ipv4(filter_src) && !is_valid_ipv6(filter_src)) {
            cerr << "Error: Invalid source IP address: " << filter_src << "\n";
            return 1;
        }
        if (!is_valid_ipv4(filter_dst) && !is_valid_ipv6(filter_dst)) {
            cerr << "Error: Invalid destination IP address: " << filter_dst << "\n";
            return 1;
        }
    } else {
        // Default filter for testing (won't match anything)
        filter_src = "0.0.0.0";
        filter_dst = "0.0.0.0";
        cout << "[Main] No filter specified, using default (no packets will match)\n";
    }

    // Display banner
    cout << "\n";
    cout << "  NETWORK MONITOR FOR PACKETS       \n";
    cout << " Interface:         " << iface << "\n";
    cout << " Filter:            " << filter_src << " -> " << filter_dst << "\n";
    cout << " Demo Duration:     60 seconds (minimum)\n";
    cout << " Requirements:      Root privileges required\n";
    cout << "\n";

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create queues
    PacketQueue<Packet> capture_queue(5000);
    PacketQueue<Packet> replay_queue(5000);
    PacketQueue<Packet> backup_queue(5000);

    // Create and start managers
    CaptureManager capture(capture_queue, iface, total_captured, 10);
    FilterManager filter(capture_queue, replay_queue, filter_src, filter_dst);
    ReplayManager replay(replay_queue, backup_queue, iface, total_replayed);
    BackupManager backup(backup_queue, replay_queue);
    DisplayManager display(capture_queue, replay_queue, backup_queue, 
                          total_captured, total_replayed);

    cout << "[Main] Starting all threads...\n";
    
    // Start all managers
    capture.start();
    this_thread::sleep_for(chrono::milliseconds(500)); // Let capture initialize
    
    filter.start();
    replay.start();
    backup.start();
    display.start();

    cout << "[Main] All threads started. Running for 60 seconds...\n";
    cout << "[Main] Press Ctrl+C to stop early.\n\n";

    // Run for at least 60 seconds (assignment requirement)
    auto start_time = chrono::steady_clock::now();
    const int DEMO_DURATION = 60; // seconds

    while (global_running) {
        auto elapsed = chrono::duration_cast<chrono::seconds>(
            chrono::steady_clock::now() - start_time).count();
        
        if (elapsed >= DEMO_DURATION) {
            cout << "\n[Main] Demo duration completed (" << DEMO_DURATION 
                 << " seconds). Initiating shutdown...\n";
            break;
        }
        
        this_thread::sleep_for(chrono::seconds(1));
    }

    // Stop all managers
    cout << "[Main] Stopping all threads...\n";
    capture.stop();
    filter.stop();
    replay.stop();
    backup.stop();
    display.stop();

    // Wait for threads to finish (give them time to cleanup)
    cout << "[Main] Waiting for threads to complete...\n";
    this_thread::sleep_for(chrono::seconds(2));

    // Display final statistics
    cout << "\n";

    cout << " FINAL REPORT AFTER PACKETS CAPTURED          \n";
    cout << " Total Packets Captured:  " << total_captured.load() << "\n";
    cout << " Total Packets Replayed:  " << total_replayed.load() << "\n";
    cout << " Capture Queue (final):   " << capture_queue.size() << " packets\n";
    cout << " Replay Queue (final):    " << replay_queue.size() << " packets\n";
    cout << " Backup Queue (final):    " << backup_queue.size() << " packets\n";
    cout << "\n";
    cout << "Network Monitor demonstration completed successfully.\n";

    // Cleanup queues
    capture_queue.clear();
    replay_queue.clear();
    backup_queue.clear();

    return 0;
}
