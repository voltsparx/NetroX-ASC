#pragma once

#include <stdint.h>

struct IntelResult {
    bool  load_balancer_hint;
    bool  zombie_valid;
    char  os_guess[64];
    char  os_vendor[32];
    uint8_t os_confidence;  // 0-100
    char  annotation[32];   // e.g. "[LOAD-BALANCER]", "[ZOMBIE]"
};

void intel_print(const IntelResult& r);
void intel_print_os(const IntelResult& r);
