#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "os_pipeline_priv.h"
#include "logger.h"

typedef struct
{
    np_pipeline_ctx_t *ctx;
    uint16_t port;
} banner_task_t;

/* --- Stage 6: Banner Grabbing Implementation --- */
static void *sub_banner_worker(void *arg)
{
    banner_task_t *task = (banner_task_t *)arg;
    int sock;
    struct sockaddr_in addr;
    char buffer[512];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        free(task);
        return NULL;
    }

    struct timeval timeout = {.tv_sec = 1, .tv_usec = 500000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(task->port);
    inet_pton(AF_INET, task->ctx->target_ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
    {
        ssize_t recvd = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (recvd > 0)
        {
            buffer[recvd] = '\0';
            pthread_mutex_lock(&pipe_mutex);
            if (task->ctx->banner_count < NP_PIPELINE_MAX_BANNER_PORTS)
            {
                int idx = task->ctx->banner_count++;
                task->ctx->banners[idx].port = task->port;
                strncpy(task->ctx->banners[idx].banner, buffer,
                        sizeof(task->ctx->banners[idx].banner) - 1);
                task->ctx->banner_valid = true;
            }
            pthread_mutex_unlock(&pipe_mutex);
        }
    }
    close(sock);
    free(task);
    return NULL;
}
