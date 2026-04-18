#include "scanner_parallel.h"
#include <unistd.h>
#include <sys/resource.h>

uint32_t np_compute_host_parallelism(const np_config_t *cfg)
{
    uint32_t host_par = NP_DEFAULT_HOST_PARALLELISM;

    /* Scale down for small target counts */
    if (cfg->target_count < host_par)
        host_par = cfg->target_count;

    /* Respect the workers flag if user set it */
    if (cfg->workers > 0 && (uint32_t)cfg->workers < host_par)
        host_par = (uint32_t)cfg->workers;

    if (cfg->max_hostgroup > 0 && host_par > cfg->max_hostgroup)
        host_par = cfg->max_hostgroup;

    if (cfg->min_hostgroup > 0 && host_par < cfg->min_hostgroup)
        host_par = cfg->min_hostgroup;

    if (host_par > cfg->target_count)
        host_par = cfg->target_count;

    /* Estimate fd usage: each host needs cfg->threads fds + overhead */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        uint32_t threads_per_host = cfg->threads ? cfg->threads : 1;
        /* Reserve 256 fds for system use */
        uint32_t available_fds = (rl.rlim_cur > 256)
                                 ? (uint32_t)(rl.rlim_cur - 256)
                                 : 64;
        uint32_t max_by_fd = available_fds / (threads_per_host + 4);
        if (max_by_fd < 1) max_by_fd = 1;
        if (host_par > max_by_fd)
            host_par = max_by_fd;
    }

    /* Hard ceiling */
    if (host_par > NP_MAX_HOST_PARALLELISM)
        host_par = NP_MAX_HOST_PARALLELISM;

    if (host_par < 1)
        host_par = 1;

    return host_par;
}
