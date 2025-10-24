# DSA-assignement2
Project Title:
Network Monitor — Packet Capture, Filter & Replay (C++)

Short Description:
A lightweight Linux user-space program written in modern C++ that captures raw Ethernet frames from a network interface, dissects IPv4/IPv6/TCP/UDP headers, filters packets by a source→destination IP pair, queues matching packets for replay, attempts to replay them on the interface with retry and backup logic, and prints live statistics. It is an educational/demo tool to illustrate raw sockets, manual packet parsing, multi-threaded producer/consumer pipelines, and simple recovery logic.

Features:
• Capture raw Ethernet frames using AF_PACKET raw sockets (Linux).
• Minimal dissector for Ethernet → IPv4 → IPv6 → TCP/UDP headers (manual parsing).
• Filter packets by source IP and destination IP (supports IPv4 and IPv6).
• Thread-safe singly-linked FIFO queues for capture, replay, and backup.
• Replay matched packets back onto the interface using sendto() on AF_PACKET.
• Retry logic for replayed packets (3 attempts) and a backup queue for failed replays with additional retry attempts.
• Oversized packet detection (simple heuristic for frames > 1500 bytes) with threshold-based skipping.
• Live console display of totals and queue sizes.
• Graceful shutdown via SIGINT/SIGTERM.

Requirements:
• Linux with AF_PACKET support.
• Root privileges or CAP_NET_RAW capability.
• g++ (or another modern C++ compiler) with C++17 support.
• pthreads support (linking via -pthread).
• No external libraries required (no libpcap dependency).

Build Instructions :

Save the program to a file named netmon.cpp.

Compile using g++: g++ -std=c++17 -O2 -pthread -Wall -Wextra -o netmon netmon.cpp

Ensure compilation succeeds and the binary "netmon" is produced.

Run / Usage (plain steps):

Run as root (or with capabilities): sudo ./netmon <interface> <src_ip> <dst_ip>
Example: sudo ./netmon eth0 192.168.1.10 192.168.1.20

Argument details:
• interface — network interface name (e.g., eth0, wlan0). Default in code: wlan0 if not provided.
• src_ip — source IP to filter (IPv4 or IPv6).
• dst_ip — destination IP to filter (IPv4 or IPv6).

If no filter is provided the program defaults to 0.0.0.0 -> 0.0.0.0 (matches nothing; capture-only mode).

The program runs for a minimum demo duration of 60 seconds or until you press Ctrl+C.

High-level architecture (how components interact):
• CaptureManager: opens AF_PACKET raw socket bound to the specified interface, reads frames via recvfrom(), wraps bytes into Packet structs, assigns id and timestamp, and pushes packets to capture_queue. It also counts oversized frames and will skip them if an internal threshold is exceeded.
• FilterManager: pulls from capture_queue, calls Dissector::dissect() to parse headers (Ethernet → IP → TCP/UDP), prints layer info, and if the packet’s parsed source and destination IP match the configured filter, pushes the Packet to replay_queue.
• ReplayManager: pulls from replay_queue, prepares a sockaddr_ll containing interface index and destination MAC (from Ethernet header), and sendto()s the raw Ethernet frame. On failure it retries up to 3 attempts; if still failing, moves the Packet to backup_queue.
• BackupManager: periodically inspects backup_queue and, for packets with replay_attempts below a higher threshold, requeues them to replay_queue for another try; otherwise marks them as permanently failed.
• DisplayManager: periodically prints totals (captured/replayed) and sizes of capture/replay/backup queues.
• global_running atomic boolean coordinates shutdown; SIGINT/SIGTERM set this flag and the main loop and manager threads exit cooperatively.

Key data structures:
• Packet struct — holds id, timestamp_ms, raw bytes (vector<uint8_t>), flags indicating parsed layers (has_ipv4/has_ipv6/has_tcp/has_udp), IP addresses and ports, and replay_attempts counter.
• PacketQueue<T> — a custom thread-safe singly-linked FIFO queue with push, pop, snapshot, size, and clear; protected with std::mutex and sized via max_size to avoid unbounded memory growth.
• SimpleStack<T> — small linked stack used by the dissector to model layered parsing.

Dissector summary :
• Ethernet header: verifies at least 14 bytes and reads Ethertype (bytes 12–13).
• IPv4: verifies version=4, reads IHL for header length, reads protocol byte to decide transport (TCP/UDP), reads source and destination IPv4 addresses.
• IPv6: validates 40-byte header, copies 16-byte source/destination addresses, reads next header field for transport.
• TCP/UDP: reads the first 4 bytes of transport header to extract source and destination ports.
• The Dissector::show_layers() function prints a human-readable summary of detected layers and addressing.

Concurrency model and safety:
• Each PacketQueue uses a std::mutex to protect list operations. push/pop lock for the operation duration.
• Atomic counters (total_captured, total_replayed) provide lock-free increments for general statistics.
• Threads are detached and cooperative — each manager owns an atomic running flag it checks. Main uses sleep waits and a global_running flag for coordinated shutdown.
• Threads sleep briefly when queues are empty to prevent busy-waiting.

Retry and backup logic:
• Replay attempts: ReplayManager tries up to 3 attempts per packet. Each failure increments packet.replay_attempts.
• BackupManager gives packets with replay_attempts less than a configured threshold another chance by moving them back to replay_queue. Packets exceeding retry limits are considered permanently failed.
• Oversized packets > 1500 bytes are tracked; if oversized_count exceeds a threshold the capture logic begins skipping oversized frames to avoid resource exhaustion.

Limitations & caveats :
• The dissector is intentionally minimal: it does not handle IPv4 fragmentation, IPv6 extension headers, TCP options, or reassembly.
• Assumes Ethernet link layer (14-byte header). Other link types need modification.
• Endianness of manually parsed integers must be carefully validated if the code is extended. Some conversions are handled with htonl() — verify correctness when changing code.
• Detached threads rely on cooperative shutdown; in rare edge cases a thread may still be running during process exit.
• Replaying captured traffic can disrupt networks and may be illegal or violate policy. Use only in lab/test networks with permission.

Troubleshooting hints:
• Permission errors creating raw sockets: run with sudo or grant CAP_NET_RAW.
• SIOCGIFINDEX failing: ensure the interface name is correct and the interface is up (check with ip link).
• No captured packets: interface may need promiscuous mode (ip link set <iface> promisc on).
• Replayed packets not seen on the network: some switches or virtual environments drop injected frames; test in a controlled lab.
• Queue full errors: increase max_size on PacketQueue constructors or reduce capture rate.

Suggested improvements :
• Use libpcap for portable capture and BPF filtering.
• Add full IPv6 extension header support and IPv4 reassembly.
• Add persistent backup storage (disk-backed queue) so backup survives restarts.
• Implement a dry-run mode (prints what would be replayed without injecting frames).
• Add logging with log levels and rotation.
• Add a web or curses-based dashboard for interactive monitoring and control.

Project organization:
• netmon.cpp 
• README.txt 
• LICENSE — choose a license (MIT recommended for educational code)
• docs/report.md — full lab report 
Author and metadata:
Author: Ayesha
Course: CS250 — Data Structures & Algorithms
Institution: NUST
Date: 2025-10-24
