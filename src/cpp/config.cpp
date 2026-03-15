#include "config.h"
#include "args.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstring>

static const uint32_t RESUME_MAGIC = 0x4E455452; // "NETR"

struct Record {
    uint32_t magic;
    uint8_t  version;
    uint8_t  scan_mode;
    uint32_t target_ip;
    uint16_t last_port;
    uint32_t rate;
};

bool save_resume(const ScanConfig& cfg, uint16_t last_port) {
    Record rec;
    rec.magic = RESUME_MAGIC;
    rec.version = 1;
    rec.scan_mode = cfg.scan_mode;
    rec.target_ip = cfg.target_ip;
    rec.last_port = last_port;
    rec.rate = cfg.rate_pps;

#ifdef _WIN32
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    std::strcat(path, "netrox_resume.bin");
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, &rec, sizeof(rec), &written, nullptr);
    CloseHandle(h);
    return ok && written == sizeof(rec);
#else
    const char* path = "/tmp/.netrox_resume";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    ssize_t w = write(fd, &rec, sizeof(rec));
    close(fd);
    return w == (ssize_t)sizeof(rec);
#endif
}

bool load_resume(ScanConfig& cfg, uint16_t& last_port) {
#ifdef _WIN32
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    std::strcat(path, "netrox_resume.bin");
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD read = 0;
    Record rec{};
    BOOL ok = ReadFile(h, &rec, sizeof(rec), &read, nullptr);
    CloseHandle(h);
    if (!ok || read != sizeof(rec) || rec.magic != RESUME_MAGIC) return false;
#else
    const char* path = "/tmp/.netrox_resume";
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    Record rec{};
    ssize_t r = read(fd, &rec, sizeof(rec));
    close(fd);
    if (r != (ssize_t)sizeof(rec) || rec.magic != RESUME_MAGIC) return false;
#endif
    cfg.scan_mode = rec.scan_mode;
    cfg.target_ip = rec.target_ip;
    cfg.rate_pps = rec.rate;
    last_port = rec.last_port;
    return true;
}

static void trim(char* s) {
    size_t len = std::strlen(s);
    while (len && (s[len-1] == '\r' || s[len-1] == '\n' || s[len-1] == ' ' || s[len-1] == '\t')) {
        s[--len] = 0;
    }
    char* p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) std::memmove(s, p, std::strlen(p) + 1);
}

bool load_config_file(const char* path, ScanConfig& cfg) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[4096] = {};
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr);
    CloseHandle(h);
    if (!ok || read == 0) return false;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    char buf[4096] = {};
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return false;
#endif
    char* line = std::strtok(buf, "\n");
    while (line) {
        trim(line);
        if (line[0] == 0 || line[0] == '#') { line = std::strtok(nullptr, "\n"); continue; }
        char* eq = std::strchr(line, '=');
        if (!eq) { line = std::strtok(nullptr, "\n"); continue; }
        *eq = 0;
        char* key = line;
        char* val = eq + 1;
        trim(key); trim(val);
        if (std::strcmp(key, "scan") == 0) cfg.scan_mode = parse_scan_mode(val);
        else if (std::strcmp(key, "rate") == 0) cfg.rate_pps = (uint32_t)std::strtoul(val, nullptr, 10);
        else if (std::strcmp(key, "ports") == 0) parse_port_spec(val, cfg);
        else if (std::strcmp(key, "iface") == 0) std::strncpy(cfg.iface, val, sizeof(cfg.iface)-1);
        else if (std::strcmp(key, "json") == 0) cfg.json_mode = 1;
        else if (std::strcmp(key, "csv") == 0) cfg.csv_mode = 1;
        line = std::strtok(nullptr, "\n");
    }
    return true;
}
