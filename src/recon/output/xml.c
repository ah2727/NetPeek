#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static void xml_escape(FILE *fp, const char *value)
{
    if (!value)
        return;

    while (*value)
    {
        switch (*value)
        {
        case '&': fputs("&amp;", fp); break;
        case '<': fputs("&lt;", fp); break;
        case '>': fputs("&gt;", fp); break;
        case '"': fputs("&quot;", fp); break;
        default: fputc(*value, fp); break;
        }
        value++;
    }
}

static np_status_t xml_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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

    fprintf(fp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(fp, "<recon run_id=\"%llu\" host_count=\"%u\">\n",
            (unsigned long long)ctx->run_id,
            host_count);

    for (uint32_t i = 0; i < host_count; i++)
    {
        fprintf(fp, "  <host ip=\"");
        xml_escape(fp, hosts[i].ip ? hosts[i].ip : "");
        fprintf(fp, "\" hostname=\"");
        xml_escape(fp, hosts[i].hostname ? hosts[i].hostname : "");
        fprintf(fp, "\">\n");

        if (include_os)
        {
            np_os_view_t *oses = NULL;
            uint32_t os_count = np_query_host_os(ctx, hosts[i].id, &oses);
            for (uint32_t j = 0; j < os_count; j++)
            {
                fprintf(fp, "    <os confidence=\"%.3f\">", oses[j].confidence);
                xml_escape(fp, oses[j].name ? oses[j].name : "");
                fprintf(fp, "</os>\n");
            }
            np_query_free(oses);
        }

        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        uint32_t identified = np_recon_count_identified_services(services, service_count);
        for (uint32_t j = 0; j < service_count; j++)
        {
            fprintf(fp, "    <service port=\"%u\" proto=\"", services[j].port);
            xml_escape(fp, services[j].proto ? services[j].proto : "");
            fprintf(fp, "\" state=\"");
            xml_escape(fp, services[j].state ? services[j].state : "");
            fprintf(fp, "\">\n");

            fprintf(fp, "      <name>");
            xml_escape(fp, services[j].service ? services[j].service : "");
            fprintf(fp, "</name>\n");

            fprintf(fp, "      <product>");
            xml_escape(fp, services[j].product ? services[j].product : "");
            fprintf(fp, "</product>\n");

            if (include_version)
            {
                fprintf(fp, "      <version>");
                xml_escape(fp, services[j].version ? services[j].version : "");
                fprintf(fp, "</version>\n");
            }

            fprintf(fp, "    </service>\n");
        }
        np_query_free(services);

        fprintf(fp, "    <report_sections>\n");
        fprintf(fp, "      <target hostname=\"");
        xml_escape(fp, hosts[i].hostname ? hosts[i].hostname : "");
        fprintf(fp, "\" ip=\"");
        xml_escape(fp, hosts[i].ip ? hosts[i].ip : "");
        fprintf(fp, "\" />\n");
        fprintf(fp, "      <coverage identified=\"%u\" total=\"%u\" />\n",
                identified,
                service_count);
        fprintf(fp, "    </report_sections>\n");

        fprintf(fp, "  </host>\n");
    }

    np_query_free(hosts);
    fprintf(fp, "</recon>\n");

    if (fp != stdout)
        fclose(fp);

    return NP_OK;
}

const np_output_module_t np_recon_output_xml_module = {
    .name = "recon.xml",
    .format = "xml",
    .extensions = "xml",
    .emit = xml_emit,
};
