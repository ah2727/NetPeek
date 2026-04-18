#ifndef NP_TCP_TYPES_H
#define NP_TCP_TYPES_H

#include <stdint.h>

#define NP_MAX_TCP_OPTIONS 16

typedef struct {
    uint8_t   kind;
    uint8_t   length;

    union {
        uint16_t mss;
        uint8_t  wscale;

        struct {
            uint32_t tsval;
            uint32_t tsecr;
        } timestamp;

        uint8_t raw[40];
    } data;

} np_tcp_option_t;

#endif