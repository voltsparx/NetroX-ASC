#pragma once

#include <stdint.h>
#include <stddef.h>

struct TargetList {
    uint32_t* ips;
    size_t    count;
    size_t    capacity;

    TargetList();
    ~TargetList();
    void add(uint32_t ip);
    void add_cidr(uint32_t base, uint8_t prefix_len);
    bool load_file(const char* path);
    void add_random(uint32_t count);
    void apply_excludes(const uint32_t* excl, size_t excl_count);
    void shuffle();
};
