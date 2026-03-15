#pragma once

#include <stdint.h>
#include <stddef.h>

#include "../../include/netrox_abi.h"

constexpr uint8_t SCAN_SYN        = 1;
constexpr uint8_t SCAN_ACK        = 2;
constexpr uint8_t SCAN_FIN        = 3;
constexpr uint8_t SCAN_NULL       = 4;
constexpr uint8_t SCAN_XMAS       = 5;
constexpr uint8_t SCAN_WINDOW     = 6;
constexpr uint8_t SCAN_MAIMON     = 7;
constexpr uint8_t SCAN_UDP        = 8;
constexpr uint8_t SCAN_PING       = 9;
constexpr uint8_t SCAN_SAR        = 10;
constexpr uint8_t SCAN_KIS        = 11;
constexpr uint8_t SCAN_PHANTOM    = 12;
constexpr uint8_t SCAN_CALLBACK   = 13;
constexpr uint8_t SCAN_CONNECT    = 14;
constexpr uint8_t SCAN_IDLE       = 15;
constexpr uint8_t SCAN_IPROTO     = 16;
constexpr uint8_t SCAN_PINGSWEEP  = 17;
constexpr uint8_t SCAN_LIST       = 18;
constexpr uint8_t SCAN_RPC        = 19;
constexpr uint8_t SCAN_SCTP_INIT  = 20;
constexpr uint8_t SCAN_SCTP_ECHO  = 21;
constexpr uint8_t SCAN_FTP_BOUNCE = 22;
constexpr uint8_t SCAN_SCRIPT     = 23;
constexpr uint8_t SCAN_AGGRESSIVE = 24;
constexpr uint8_t SCAN_SEQ        = 25;
constexpr uint8_t SCAN_ICMP_TS    = 26;
constexpr uint8_t SCAN_ICMP_NM    = 27;
constexpr uint8_t SCAN_ARP        = 28;

bool parse_args(int argc, char** argv, ScanConfig& cfg);
void print_usage();

// Internal helpers (also usable by targets.cpp)
uint32_t parse_ip(const char* s);        // returns 0 on error
bool     parse_cidr(const char* s, uint32_t& base, uint8_t& prefix_len);
bool     parse_port_spec(const char* s, ScanConfig& cfg);
uint8_t  parse_scan_mode(const char* s); // returns SCAN_xxx constant
uint64_t parse_timespec(const char* s);  // returns microseconds
bool     parse_ip_port(const char* s, uint32_t& ip, uint16_t& port);

// Target-related extras
const char* get_iL_path();
const char* get_excludefile_path();
const uint32_t* get_exclude_list(size_t& count);
bool get_help_mode();
bool get_about_mode();
bool get_echo_mode();
bool get_wizard_mode();
bool get_no_color();
bool get_iflist_mode();
bool get_version_mode();
bool get_skip_discovery();
bool get_ping_only_mode();
uint8_t get_disc_icmp_type();
bool get_traceroute_mode();
uint32_t get_random_count();
uint64_t get_min_rtt_timeout();
uint64_t get_max_rtt_timeout();
uint64_t get_initial_rtt_timeout();
uint32_t get_min_hostgroup();
uint32_t get_max_hostgroup();
