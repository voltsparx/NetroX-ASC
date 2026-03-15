#include "intel.h"
#include "output.h"
#include "color.h"

void intel_print(const IntelResult& r) {
    if (r.annotation[0]) {
        out_str(ColorGuard::yellow());
        out_str(r.annotation);
        out_str(ColorGuard::reset());
        out_str(" ");
    }
}

void intel_print_os(const IntelResult& r) {
    if (r.os_guess[0]) {
        out_str(r.os_guess);
        out_str(" (");
        out_uint(r.os_confidence);
        out_str("%)");
    }
}
