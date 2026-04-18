#ifndef NP_FAST_TX_H
#define NP_FAST_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct np_fast_tx_ctx
{
    int fd;
    void *ring;
    size_t ring_len;
    uint32_t frame_count;
    uint32_t frame_size;
    uint32_t frame_idx;
    uint8_t src_mac_override[6];
    bool has_src_mac_override;
    bool enabled;
} np_fast_tx_ctx_t;

typedef struct np_fast_rx_ctx
{
    int fd;
    void *ring;
    size_t ring_len;
    uint32_t frame_count;
    uint32_t frame_size;
    bool enabled;
} np_fast_rx_ctx_t;

int np_fast_tx_init(np_fast_tx_ctx_t *ctx,
                    const char *ifname,
                    uint32_t frame_count,
                    uint32_t frame_size);
int np_fast_tx_send(np_fast_tx_ctx_t *ctx, const void *packet, size_t len);
void np_fast_tx_set_src_mac(np_fast_tx_ctx_t *ctx, const uint8_t mac[6]);
void np_fast_tx_clear_src_mac(np_fast_tx_ctx_t *ctx);
void np_fast_tx_close(np_fast_tx_ctx_t *ctx);

int np_fast_rx_init(np_fast_rx_ctx_t *ctx,
                    const char *ifname,
                    uint32_t frame_count,
                    uint32_t frame_size,
                    uint32_t fanout_group,
                    uint32_t fanout_type);
ssize_t np_fast_rx_next(np_fast_rx_ctx_t *ctx, const void **packet_out);
void np_fast_rx_release(np_fast_rx_ctx_t *ctx);
void np_fast_rx_close(np_fast_rx_ctx_t *ctx);

#endif
