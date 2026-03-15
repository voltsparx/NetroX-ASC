#include "targets.h"
#include "args.h"

#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

TargetList::TargetList() : ips(nullptr), count(0), capacity(0) {}
TargetList::~TargetList() { std::free(ips); }

void TargetList::add(uint32_t ip) {
    if (count + 1 > capacity) {
        size_t newcap = capacity ? capacity * 2 : 256;
        uint32_t* n = (uint32_t*)std::realloc(ips, newcap * sizeof(uint32_t));
        if (!n) return;
        ips = n;
        capacity = newcap;
    }
    ips[count++] = ip;
}

void TargetList::add_cidr(uint32_t base, uint8_t prefix_len) {
    if (prefix_len > 32) return;
    uint32_t host_bits = 32 - prefix_len;
    uint32_t total = (host_bits >= 31) ? 0 : (1u << host_bits);
    if (total == 0) return;
    if (total > 65536) total = 65536;
    uint32_t first = base + 1;
    for (uint32_t i = 0; i < total - 2; ++i) add(first + i);
}

bool TargetList::load_file(const char* path) {
    if (!path) return false;
#ifdef _WIN32
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[4096] = {};
    DWORD read = 0;
    if (!ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr)) { CloseHandle(h); return false; }
    CloseHandle(h);
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    char buf[4096] = {};
    ssize_t read = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (read <= 0) return false;
#endif
    char* line = std::strtok(buf, "\n");
    while (line) {
        if (line[0] == 0 || line[0] == '#') { line = std::strtok(nullptr, "\n"); continue; }
        uint32_t base = 0; uint8_t pref = 0;
        if (parse_cidr(line, base, pref)) add_cidr(base, pref);
        else {
            uint32_t ip = parse_ip(line);
            if (ip) add(ip);
        }
        line = std::strtok(nullptr, "\n");
    }
    return true;
}

static uint64_t xstate = 0xDEADBEEFCAFEBABEULL;
static uint64_t xnext() {
    xstate ^= xstate << 13;
    xstate ^= xstate >> 7;
    xstate ^= xstate << 17;
    return xstate;
}

void TargetList::add_random(uint32_t count) {
    for (uint32_t i = 0; i < count; ) {
        uint32_t ip = (uint32_t)(xnext() & 0xFFFFFFFFu);
        uint8_t a = (ip >> 24) & 0xFF;
        uint8_t b = (ip >> 16) & 0xFF;
        if (a == 0 || a == 10 || a == 127 || a >= 224) continue;
        if (a == 169 && b == 254) continue;
        if (a == 172 && (b >= 16 && b <= 31)) continue;
        if (a == 192 && b == 168) continue;
        add(ip);
        i++;
    }
}

void TargetList::apply_excludes(const uint32_t* excl, size_t excl_count) {
    if (!excl || excl_count == 0) return;
    size_t out = 0;
    for (size_t i = 0; i < count; ++i) {
        bool skip = false;
        for (size_t j = 0; j < excl_count; ++j) {
            if (ips[i] == excl[j]) { skip = true; break; }
        }
        if (!skip) ips[out++] = ips[i];
    }
    count = out;
}

void TargetList::shuffle() {
    if (count <= 1) return;
    for (size_t i = count - 1; i > 0; --i) {
        size_t j = (size_t)(xnext() % (i + 1));
        uint32_t tmp = ips[i];
        ips[i] = ips[j];
        ips[j] = tmp;
    }
}
