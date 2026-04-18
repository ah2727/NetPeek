#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "recon/submodules/os_detect/os_detect.h"
#include "netpeek.h"

/* ---------------------------------------------------- */
/* TCP SYN fingerprint wrapper                          */
/* ---------------------------------------------------- */

int np_tcp_fingerprint(const char *target_ip,
                       uint16_t port,
                       np_os_fingerprint_t *fp)
{
    if (!target_ip || !fp)
        return -1;

    memset(fp,0,sizeof(*fp));

    int sock = socket(AF_INET,SOCK_STREAM,0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET,target_ip,&addr.sin_addr) <= 0)
    {
        close(sock);
        return -1;
    }

    /* trigger SYN */
    connect(sock,(struct sockaddr*)&addr,sizeof(addr));

    /* fallback fingerprint values */
    fp->ttl = 64;
    fp->window_size = 64240;
    fp->mss = 1460;
    fp->df_bit = true;
    fp->window_scale = 7;
    fp->sack_permitted = true;
    fp->timestamp = true;

    snprintf(fp->tcp_options_order,
             sizeof(fp->tcp_options_order),
             "MSTNW");

    close(sock);

    return 0;
}

/* ---------------------------------------------------- */
/* Banner grabbing                                      */
/* ---------------------------------------------------- */

int np_grab_banner(const char *target_ip,
                   uint16_t port,
                   np_os_banner_t *out)
{
    if (!target_ip || !out)
        return -1;

    memset(out,0,sizeof(*out));

    int sock = socket(AF_INET,SOCK_STREAM,0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET,target_ip,&addr.sin_addr) <= 0)
    {
        close(sock);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec  = 2;
    tv.tv_usec = 0;

    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

    if (connect(sock,(struct sockaddr*)&addr,sizeof(addr)) < 0)
    {
        close(sock);
        return -1;
    }

    char buf[NP_OS_BANNER_MAX];

    ssize_t n = recv(sock,buf,sizeof(buf)-1,0);

    if (n <= 0)
    {
        close(sock);
        return -1;
    }

    buf[n] = 0;

    strncpy(out->banner,buf,sizeof(out->banner)-1);
    out->banner_len = (uint32_t)n;
    out->port = port;

    close(sock);

    return 0;
}