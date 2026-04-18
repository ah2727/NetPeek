#ifndef NP_SUBENUM_DNS_PACKET_H
#define NP_SUBENUM_DNS_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include "subenum/subenum_types.h"

typedef struct
{
    char name[512];
    uint16_t type;
    uint32_t ttl;
    char value[1024];
} np_dns_answer_t;

int np_dns_encode_name(const char *name, uint8_t *out, size_t outlen);
int np_dns_decode_name(const uint8_t *pkt, size_t pktlen,
                       size_t *offset, char *out, size_t outlen);
int np_dns_build_query(uint8_t *buf, size_t buflen,
                       uint16_t txid, const char *name,
                       np_dns_record_type_t qtype);
int np_dns_parse_response(const uint8_t *buf, size_t len,
                          np_dns_answer_t *answers, size_t max_answers,
                          uint16_t *out_txid);

#endif
