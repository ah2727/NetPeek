#ifndef SYN_SCAN_H
#define SYN_SCAN_H

#include <stdint.h>
#include <sys/time.h>

#define MAX_PROBES 1024

struct syn_probe {
    uint16_t src_port;
    uint16_t dst_port;
    struct timeval sent_at;
    int answered;
};

extern int probe_count;

void start_sniffer(const char *iface);

#endif