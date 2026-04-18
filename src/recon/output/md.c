#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static np_status_t md_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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
    bool include_version = np_recon_should_show_version(ctx);
    bool include_os = np_recon_should_show_os(ctx);

    fprintf(fp, "# NetPeek Recon Report\n\n");
    fprintf(fp, "- Run ID: `%llu`\n", (unsigned long long)ctx->run_id);
    fprintf(fp, "- Hosts: `%u`\n\n", host_count);

    for (uint32_t i = 0; i < host_count; i++)
    {
        const char *ip = hosts[i].ip && hosts[i].ip[0] ? hosts[i].ip : "unknown";
        const char *hostname = hosts[i].hostname && hosts[i].hostname[0] ? hosts[i].hostname : "unknown";

        fprintf(fp, "## Host %s (%s)\n\n", ip, hostname);

        np_os_view_t *oses = NULL;
        uint32_t os_count = np_query_host_os(ctx, hosts[i].id, &oses);
        if (include_os)
        {
            if (os_count > 0)
                fprintf(fp, "- OS: %s (%.0f%%)\n", oses[0].name ? oses[0].name : "unknown", oses[0].confidence * 100.0);
            else
                fprintf(fp, "- OS: unknown\n");
        }
        np_query_free(oses);

        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        uint32_t identified = np_recon_count_identified_services(services, service_count);
        if (service_count == 0)
        {
            fprintf(fp, "- Services: none\n\n");
            np_query_free(services);
        }
        else
        {
            if (include_version)
            {
                fprintf(fp, "\n| Port | Proto | Service | State | Version |\n");
                fprintf(fp, "|---:|---|---|---|---|\n");
            }
            else
            {
                fprintf(fp, "\n| Port | Proto | Service | State |\n");
                fprintf(fp, "|---:|---|---|---|\n");
            }
            for (uint32_t j = 0; j < service_count; j++)
            {
                if (include_version)
                {
                    fprintf(fp,
                            "| %u | %s | %s | %s | %s %s |\n",
                            services[j].port,
                            services[j].proto ? services[j].proto : "tcp",
                            services[j].service ? services[j].service : "unknown",
                            services[j].state ? services[j].state : "unknown",
                            services[j].product ? services[j].product : "",
                            services[j].version ? services[j].version : "");
                }
                else
                {
                    fprintf(fp,
                            "| %u | %s | %s | %s |\n",
                            services[j].port,
                            services[j].proto ? services[j].proto : "tcp",
                            services[j].service ? services[j].service : "unknown",
                            services[j].state ? services[j].state : "unknown");
                }
            }
            fprintf(fp, "\n");
        }

        fprintf(fp, "### Report Sections\n\n");
        fprintf(fp, "- Coverage: %u/%u services identified\n", identified, service_count);
        fprintf(fp, "\n");

        np_query_free(services);
    }

    np_query_free(hosts);

    if (fp != stdout)
        fclose(fp);

    return NP_OK;
}

const np_output_module_t np_recon_output_md_module = {
    .name = "recon.md",
    .format = "md",
    .extensions = "md markdown",
    .emit = md_emit,
};
