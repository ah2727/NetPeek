#include "subenum/dns_packet.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int np_dns_encode_name(const char *name, uint8_t *out, size_t outlen)
{
    const char *p = name;
    size_t pos = 0;
    if (!name || !out)
        return -1;

    while (*p)
    {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len == 0 || label_len > 63 || pos + 1 + label_len >= outlen)
            return -1;
        out[pos++] = (uint8_t)label_len;
        memcpy(out + pos, p, label_len);
        pos += label_len;
        if (!dot)
            break;
        p = dot + 1;
    }
    if (pos + 1 > outlen)
        return -1;
    out[pos++] = 0;
    return (int)pos;
}

int np_dns_decode_name(const uint8_t *pkt, size_t pktlen,
                       size_t *offset, char *out, size_t outlen)
{
    size_t pos;
    size_t out_pos = 0;
    size_t jump_save = 0;
    int jumped = 0;
    int jumps = 0;

    if (!pkt || !offset || !out || outlen == 0)
        return -1;

    pos = *offset;
    while (pos < pktlen)
    {
        uint8_t len = pkt[pos];
        if (len == 0)
        {
            pos++;
            break;
        }
        if ((len & 0xC0) == 0xC0)
        {
            size_t ptr;
            if (pos + 1 >= pktlen)
                return -1;
            ptr = (size_t)(((len & 0x3F) << 8) | pkt[pos + 1]);
            if (ptr >= pktlen)
                return -1;
            if (!jumped)
            {
                jumped = 1;
                jump_save = pos + 2;
            }
            pos = ptr;
            if (++jumps > 256)
                return -1;
            continue;
        }

        pos++;
        if (pos + len > pktlen)
            return -1;
        if (out_pos && out_pos + 1 < outlen)
            out[out_pos++] = '.';
        if (out_pos + len >= outlen)
            return -1;
        memcpy(out + out_pos, pkt + pos, len);
        out_pos += len;
        pos += len;
    }

    out[out_pos] = '\0';
    *offset = jumped ? jump_save : pos;
    return 0;
}

int np_dns_build_query(uint8_t *buf, size_t buflen,
                       uint16_t txid, const char *name,
                       np_dns_record_type_t qtype)
{
    size_t pos = 12;
    int enc_len;
    if (!buf || buflen < 64 || !name)
        return -1;

    memset(buf, 0, buflen);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01;
    buf[5] = 0x01;

    enc_len = np_dns_encode_name(name, buf + pos, buflen - pos);
    if (enc_len < 0)
        return -1;
    pos += (size_t)enc_len;

    if (pos + 4 > buflen)
        return -1;
    buf[pos++] = (uint8_t)(((uint16_t)qtype) >> 8);
    buf[pos++] = (uint8_t)(((uint16_t)qtype) & 0xFF);
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;

    return (int)pos;
}

int np_dns_parse_response(const uint8_t *buf, size_t len,
                          np_dns_answer_t *answers, size_t max_answers,
                          uint16_t *out_txid)
{
    uint16_t qdcount;
    uint16_t ancount;
    size_t offset = 12;
    size_t out_count = 0;
    uint16_t i;

    if (!buf || len < 12)
        return -1;
    if (out_txid)
        *out_txid = read_u16(buf);

    qdcount = read_u16(buf + 4);
    ancount = read_u16(buf + 6);

    for (i = 0; i < qdcount; i++)
    {
        if (np_dns_decode_name(buf, len, &offset, (char[512]){0}, 512) != 0)
            return -1;
        if (offset + 4 > len)
            return -1;
        offset += 4;
    }

    for (i = 0; i < ancount; i++)
    {
        char name[512] = {0};
        uint16_t type;
        uint16_t rdlen;
        uint32_t ttl;

        if (np_dns_decode_name(buf, len, &offset, name, sizeof(name)) != 0)
            return (int)out_count;
        if (offset + 10 > len)
            return (int)out_count;

        type = read_u16(buf + offset);
        ttl = read_u32(buf + offset + 4);
        rdlen = read_u16(buf + offset + 8);
        offset += 10;
        if (offset + rdlen > len)
            return (int)out_count;

        if (answers && out_count < max_answers)
        {
            np_dns_answer_t *ans = &answers[out_count];
            memset(ans, 0, sizeof(*ans));
            strncpy(ans->name, name, sizeof(ans->name) - 1);
            ans->type = type;
            ans->ttl = ttl;

            if (type == NP_DNS_REC_A && rdlen == 4)
            {
                inet_ntop(AF_INET, buf + offset, ans->value, sizeof(ans->value));
            }
            else if (type == NP_DNS_REC_AAAA && rdlen == 16)
            {
                inet_ntop(AF_INET6, buf + offset, ans->value, sizeof(ans->value));
            }
            else if (type == NP_DNS_REC_CNAME || type == NP_DNS_REC_NS || type == NP_DNS_REC_PTR)
            {
                size_t tmp = offset;
                if (np_dns_decode_name(buf, len, &tmp, ans->value, sizeof(ans->value)) != 0)
                    ans->value[0] = '\0';
            }
        }

        if (answers && out_count < max_answers)
            out_count++;
        offset += rdlen;
    }

    return (int)out_count;
}
