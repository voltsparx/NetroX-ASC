#include "output.h"

void csv_header() {
    out_str("port,proto,state,service,version,rtt_ns\n");
}

void csv_port(const PortResult& r) {
    out_uint(r.port);
    out_str(",tcp,");
    out_str(r.state == 1 ? "open" : (r.state == 2 ? "filtered" : "closed"));
    out_str(",");
    out_str(r.service);
    out_str(",");
    out_str(r.version);
    out_str(",");
    out_uint(r.rtt_ns);
    out_str("\n");
}
