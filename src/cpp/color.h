#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

constexpr const char* CLR_RED    = "\033[91m";
constexpr const char* CLR_YELLOW = "\033[93m";
constexpr const char* CLR_GREEN  = "\033[92m";
constexpr const char* CLR_CYAN   = "\033[36m";
constexpr const char* CLR_WHITE  = "\033[97m";
constexpr const char* CLR_GRAY   = "\033[37m";
constexpr const char* CLR_RESET  = "\033[0m";

class ColorGuard {
public:
    static inline bool enabled = false;

    static inline void init() {
#ifdef _WIN32
        DWORD mode = 0;
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
            enabled = true;
        } else {
            enabled = false;
        }
#else
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
            enabled = true;
        } else {
            enabled = false;
        }
#endif
    }

    static inline void disable() { enabled = false; }

    static inline const char* red()    { return enabled ? CLR_RED    : ""; }
    static inline const char* yellow() { return enabled ? CLR_YELLOW : ""; }
    static inline const char* green()  { return enabled ? CLR_GREEN  : ""; }
    static inline const char* cyan()   { return enabled ? CLR_CYAN   : ""; }
    static inline const char* gray()   { return enabled ? CLR_GRAY   : ""; }
    static inline const char* white()  { return enabled ? CLR_WHITE  : ""; }
    static inline const char* reset()  { return enabled ? CLR_RESET  : ""; }
};
