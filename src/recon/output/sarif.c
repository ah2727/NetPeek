#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static void json_escape(FILE *fp, const char *value)
{
    if (!value)
        return;

    while (*value)
    {
        switch (*value)
        {
        case '"': fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n", fp); break;
        case '\r': fputs("\\r", fp); break;
        case '\t': fputs("\\t", fp); break;
        default: fputc(*value, fp); break;
        }
        value++;
    }
}

static np_status_t sarif_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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

    fprintf(fp, "{\n");
    fprintf(fp, "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    fprintf(fp, "  \"version\": \"2.1.0\",\n");
    fprintf(fp, "  \"runs\": [{\n");
    fprintf(fp, "    \"tool\": {\"driver\": {\"name\": \"NetPeek Recon\", \"version\": \"1\"}},\n");

    fprintf(fp, "    \"results\": [\n");

    np_host_view_t *hosts = NULL;
    uint32_t host_count = np_query_hosts(ctx, &hosts);
    bool first_result = true;

    for (uint32_t i = 0; i < host_count; i++)
    {
        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        uint32_t identified = np_recon_count_identified_services(services, service_count);
        for (uint32_t j = 0; j < service_count; j++)
        {
            if (!first_result)
                fprintf(fp, ",\n");
            first_result = false;

            const char *ip = hosts[i].ip ? hosts[i].ip : "unknown";
            const char *proto = services[j].proto ? services[j].proto : "tcp";
            const char *svc = services[j].service ? services[j].service : "unknown";
            const char *state = services[j].state ? services[j].state : "unknown";

            fprintf(fp, "      {\"ruleId\": \"NP.OPEN.SERVICE\", \"level\": \"note\", \"message\": {\"text\": \"");
            json_escape(fp, ip);
            fprintf(fp, ":%u/", services[j].port);
            json_escape(fp, proto);
            fprintf(fp, " ");
            json_escape(fp, svc);
            fprintf(fp,
                    " (%s)\"}, \"properties\": {\"target\": \"",
                    state);
            json_escape(fp, ip);
            fprintf(fp,
                    "\", \"coverage\": {\"identified\": %u, \"total\": %u}}}",
                    identified,
                    service_count);
        }
        np_query_free(services);
    }

    np_query_free(hosts);

    fprintf(fp, "\n    ]\n");
    fprintf(fp, "  }]\n");
    fprintf(fp, "}\n");

    if (fp != stdout)
        fclose(fp);

    return NP_OK;
}

const np_output_module_t np_recon_output_sarif_module = {
    .name = "recon.sarif",
    .format = "sarif",
    .extensions = "sarif",
    .emit = sarif_emit,
};
