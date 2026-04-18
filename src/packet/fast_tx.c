#include "packet/fast_tx.h"

#include <string.h>

#if defined(__linux__)

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

static void np_fast_reset_tx(np_fast_tx_ctx_t *ctx)
{
    if (!ctx)
        return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = -1;
}

static void np_fast_reset_rx(np_fast_rx_ctx_t *ctx)
{
    if (!ctx)
        return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = -1;
}

int np_fast_tx_init(np_fast_tx_ctx_t *ctx,
                    const char *ifname,
                    uint32_t frame_count,
                    uint32_t frame_size)
{
    if (!ctx || !ifname || frame_count == 0 || frame_size == 0)
        return -1;

    np_fast_reset_tx(ctx);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        close(fd);
        return -1;
    }

    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_frame_nr = frame_count;
    req.tp_frame_size = frame_size;
    req.tp_block_size = frame_size * frame_count;
    req.tp_block_nr = 1;

    if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0)
    {
        close(fd);
        return -1;
    }

    size_t ring_len = (size_t)req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED)
    {
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        munmap(ring, ring_len);
        close(fd);
        return -1;
    }

    ctx->fd = fd;
    ctx->ring = ring;
    ctx->ring_len = ring_len;
    ctx->frame_count = frame_count;
    ctx->frame_size = frame_size;
    ctx->frame_idx = 0;
    ctx->enabled = true;
    return 0;
}

int np_fast_tx_send(np_fast_tx_ctx_t *ctx, const void *packet, size_t len)
{
    if (!ctx || !ctx->enabled || ctx->fd < 0 || !ctx->ring || !packet)
        return -1;

    if (len > ctx->frame_size)
        return -1;

    uint8_t *frame_base = (uint8_t *)ctx->ring + ((size_t)ctx->frame_idx * ctx->frame_size);
    struct tpacket_hdr *hdr = (struct tpacket_hdr *)frame_base;

    if (!(hdr->tp_status & TP_STATUS_AVAILABLE))
        return -1;

    uint8_t *payload = frame_base + TPACKET_HDRLEN;
    memcpy(payload, packet, len);
    if (ctx->has_src_mac_override && len >= 12)
        memcpy(payload + 6, ctx->src_mac_override, 6);
    hdr->tp_len = (unsigned int)len;
    hdr->tp_snaplen = (unsigned int)len;
    hdr->tp_status = TP_STATUS_SEND_REQUEST;

    ctx->frame_idx = (ctx->frame_idx + 1) % ctx->frame_count;

    if (send(ctx->fd, NULL, 0, MSG_DONTWAIT) < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }

    return 0;
}

void np_fast_tx_set_src_mac(np_fast_tx_ctx_t *ctx, const uint8_t mac[6])
{
    if (!ctx || !mac)
        return;
    memcpy(ctx->src_mac_override, mac, 6);
    ctx->has_src_mac_override = true;
}

void np_fast_tx_clear_src_mac(np_fast_tx_ctx_t *ctx)
{
    if (!ctx)
        return;
    memset(ctx->src_mac_override, 0, sizeof(ctx->src_mac_override));
    ctx->has_src_mac_override = false;
}

void np_fast_tx_close(np_fast_tx_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->ring && ctx->ring_len)
        munmap(ctx->ring, ctx->ring_len);
    if (ctx->fd >= 0)
        close(ctx->fd);

    np_fast_reset_tx(ctx);
}

int np_fast_rx_init(np_fast_rx_ctx_t *ctx,
                    const char *ifname,
                    uint32_t frame_count,
                    uint32_t frame_size,
                    uint32_t fanout_group,
                    uint32_t fanout_type)
{
    if (!ctx || !ifname || frame_count == 0 || frame_size == 0)
        return -1;

    np_fast_reset_rx(ctx);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        close(fd);
        return -1;
    }

    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_frame_nr = frame_count;
    req.tp_frame_size = frame_size;
    req.tp_block_size = frame_size * frame_count;
    req.tp_block_nr = 1;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0)
    {
        close(fd);
        return -1;
    }

    int fanout = (int)((fanout_group & 0xffffu) | ((fanout_type & 0xffffu) << 16));
    (void)setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout, sizeof(fanout));

    size_t ring_len = (size_t)req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED)
    {
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        munmap(ring, ring_len);
        close(fd);
        return -1;
    }

    ctx->fd = fd;
    ctx->ring = ring;
    ctx->ring_len = ring_len;
    ctx->frame_count = frame_count;
    ctx->frame_size = frame_size;
    ctx->enabled = true;
    return 0;
}

ssize_t np_fast_rx_next(np_fast_rx_ctx_t *ctx, const void **packet_out)
{
    if (!ctx || !ctx->enabled || !ctx->ring || !packet_out)
        return -1;

    for (uint32_t i = 0; i < ctx->frame_count; i++)
    {
        uint8_t *frame_base = (uint8_t *)ctx->ring + ((size_t)i * ctx->frame_size);
        struct tpacket_hdr *hdr = (struct tpacket_hdr *)frame_base;
        if (!(hdr->tp_status & TP_STATUS_USER))
            continue;

        *packet_out = frame_base + hdr->tp_mac;
        return (ssize_t)hdr->tp_snaplen;
    }

    return 0;
}

void np_fast_rx_release(np_fast_rx_ctx_t *ctx)
{
    if (!ctx || !ctx->enabled || !ctx->ring)
        return;

    for (uint32_t i = 0; i < ctx->frame_count; i++)
    {
        uint8_t *frame_base = (uint8_t *)ctx->ring + ((size_t)i * ctx->frame_size);
        struct tpacket_hdr *hdr = (struct tpacket_hdr *)frame_base;
        if (hdr->tp_status & TP_STATUS_USER)
        {
            hdr->tp_status = TP_STATUS_KERNEL;
            return;
        }
    }
}

void np_fast_rx_close(np_fast_rx_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->ring && ctx->ring_len)
        munmap(ctx->ring, ctx->ring_len);
    if (ctx->fd >= 0)
        close(ctx->fd);

    np_fast_reset_rx(ctx);
}

#else

int np_fast_tx_init(np_fast_tx_ctx_t *ctx,
                    const char *ifname,
                    uint32_t frame_count,
                    uint32_t frame_size)
{
    (void)ctx;
    (void)ifname;
    (void)frame_count;
    (void)frame_size;
    return -1;
}

int np_fast_tx_send(np_fast_tx_ctx_t *ctx, const void *packet, size_t len)
{
    (void)ctx;
    (void)packet;
    (void)len;
    return -1;
}

void np_fast_tx_set_src_mac(np_fast_tx_ctx_t *ctx, const uint8_t mac[6])
{
    (void)ctx;
    (void)mac;
}

void np_fast_tx_clear_src_mac(np_fast_tx_ctx_t *ctx)
{
    (void)ctx;
}

void np_fast_tx_close(np_fast_tx_ctx_t *ctx)
{
    (void)ctx;
}

int np_fast_rx_init(np_fast_rx_ctx_t *ctx,
                    const char *ifname,
                    uint32_t frame_count,
                    uint32_t frame_size,
                    uint32_t fanout_group,
                    uint32_t fanout_type)
{
    (void)ctx;
    (void)ifname;
    (void)frame_count;
    (void)frame_size;
    (void)fanout_group;
    (void)fanout_type;
    return -1;
}

ssize_t np_fast_rx_next(np_fast_rx_ctx_t *ctx, const void **packet_out)
{
    (void)ctx;
    (void)packet_out;
    return -1;
}

void np_fast_rx_release(np_fast_rx_ctx_t *ctx)
{
    (void)ctx;
}

void np_fast_rx_close(np_fast_rx_ctx_t *ctx)
{
    (void)ctx;
}

#endif
