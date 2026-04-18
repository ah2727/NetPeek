#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static np_status_t diff_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
{
    if (!ctx || !cfg)
        return NP_ERR_ARGS;

    FILE *fp = stdout;
    if (cfg->path)
    {
        fp = fopen(cfg->path, "w");
        if (!fp)
            return NP_ERR_SYSTEM;
    }

    np_host_view_t *hosts = NULL;
    uint32_t host_count = np_query_hosts(ctx, &hosts);
    np_recon_perf_t perf;
    np_recon_estimate_performance(ctx, &perf);

    fprintf(fp, "# NetPeek Recon Snapshot\n");
    fprintf(fp, "# run_id=%llu hosts=%u\n", (unsigned long long)ctx->run_id, host_count);
    fprintf(fp, "# perf total=%.2fs discovery=%.2fs enum=%.2fs fp=%.2fs os=%.2fs\n",
            perf.total_seconds,
            perf.stages[0].seconds,
            perf.stages[1].seconds,
            perf.stages[2].seconds,
            perf.stages[3].seconds);

    for (uint32_t i = 0; i < host_count; i++)
    {
        const char *ip = hosts[i].ip && hosts[i].ip[0] ? hosts[i].ip : "unknown";

        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        uint32_t identified = np_recon_count_identified_services(services, service_count);
        fprintf(fp, "~ coverage %s identified=%u total=%u\n", ip, identified, service_count);
        for (uint32_t j = 0; j < service_count; j++)
        {
            fprintf(fp,
                    "+ %s:%u/%s %s",
                    ip,
                    services[j].port,
                    services[j].proto ? services[j].proto : "tcp",
                    services[j].service ? services[j].service : "unknown");

            if (services[j].version && services[j].version[0])
                fprintf(fp, " %s", services[j].version);
            fprintf(fp, "\n");
        }

        np_query_free(services);
    }

    np_query_free(hosts);

    if (fp != stdout)
        fclose(fp);

    return NP_OK;
}

const np_output_module_t np_recon_output_diff_module = {
    .name = "recon.diff",
    .format = "diff",
    .extensions = "diff patch",
    .emit = diff_emit,
};
