#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static void csv_write_field(FILE *fp, const char *value)
{
    if (!value)
    {
        fputs("\"\"", fp);
        return;
    }

    fputc('"', fp);
    while (*value)
    {
        if (*value == '"')
            fputc('"', fp);
        fputc(*value, fp);
        value++;
    }
    fputc('"', fp);
}

static np_status_t csv_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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

    bool include_version = np_recon_should_show_version(ctx);
    bool include_os = np_recon_should_show_os(ctx);

    fprintf(fp, "host,ip,port,proto,state,service,product");
    if (include_version)
        fprintf(fp, ",version");
    if (include_os)
        fprintf(fp, ",os,os_confidence");
    fprintf(fp, ",coverage_identified,coverage_total\n");

    np_host_view_t *hosts = NULL;
    uint32_t host_count = np_query_hosts(ctx, &hosts);

    for (uint32_t i = 0; i < host_count; i++)
    {
        np_os_view_t *oses = NULL;
        uint32_t os_count = 0;
        if (include_os)
            os_count = np_query_host_os(ctx, hosts[i].id, &oses);
        const char *os_name = (os_count > 0 && oses[0].name) ? oses[0].name : "";
        double os_conf = (os_count > 0) ? oses[0].confidence : 0.0;

        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        uint32_t identified = np_recon_count_identified_services(services, service_count);

        if (service_count == 0)
        {
            csv_write_field(fp, hosts[i].hostname ? hosts[i].hostname : "");
            fputc(',', fp);
            csv_write_field(fp, hosts[i].ip ? hosts[i].ip : "");
            fprintf(fp, ",,,,,");
            if (include_version)
                fputc(',', fp);
            if (include_os)
            {
                fputc(',', fp);
                csv_write_field(fp, os_name);
                fprintf(fp, ",%.3f", os_conf);
            }
            fprintf(fp, ",%u,%u\n", identified, service_count);
        }
        else
        {
            for (uint32_t j = 0; j < service_count; j++)
            {
                csv_write_field(fp, hosts[i].hostname ? hosts[i].hostname : "");
                fputc(',', fp);
                csv_write_field(fp, hosts[i].ip ? hosts[i].ip : "");
                fprintf(fp, ",%u,", services[j].port);
                csv_write_field(fp, services[j].proto ? services[j].proto : "");
                fputc(',', fp);
                csv_write_field(fp, services[j].state ? services[j].state : "");
                fputc(',', fp);
                csv_write_field(fp, services[j].service ? services[j].service : "");
                fputc(',', fp);
                csv_write_field(fp, services[j].product ? services[j].product : "");
                if (include_version)
                {
                    fputc(',', fp);
                    csv_write_field(fp, services[j].version ? services[j].version : "");
                }
                if (include_os)
                {
                    fputc(',', fp);
                    csv_write_field(fp, os_name);
                    fprintf(fp, ",%.3f", os_conf);
                }
                fprintf(fp, ",%u,%u\n", identified, service_count);
            }
        }

        np_query_free(services);
        np_query_free(oses);
    }

    np_query_free(hosts);

    if (fp != stdout)
        fclose(fp);

    return NP_OK;
}

const np_output_module_t np_recon_output_csv_module = {
    .name = "recon.csv",
    .format = "csv",
    .extensions = "csv",
    .emit = csv_emit,
};
