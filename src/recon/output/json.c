#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static void json_escape(FILE *fp, const char *s)
{
    if (!s)
        return;
    while (*s)
    {
        switch (*s)
        {
        case '"': fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n", fp); break;
        case '\r': fputs("\\r", fp); break;
        case '\t': fputs("\\t", fp); break;
        default: fputc(*s, fp); break;
        }
        s++;
    }
}

static np_status_t json_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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
    fprintf(fp, "  \"run\": {\"id\": %llu, \"timestamp\": %lld},\n",
            (unsigned long long)ctx->run_id,
            (long long)ctx->start_ts);
    fprintf(fp, "  \"hosts\": [\n");

    bool include_version = np_recon_should_show_version(ctx);
    bool include_os = np_recon_should_show_os(ctx);
    np_host_view_t *hosts = NULL;
    uint32_t host_count = np_query_hosts(ctx, &hosts);
    for (uint32_t i = 0; i < host_count; i++)
    {
        fprintf(fp, "    {\"ip\": \"");
        json_escape(fp, hosts[i].ip ? hosts[i].ip : "");
        fprintf(fp, "\", \"hostname\": \"");
        json_escape(fp, hosts[i].hostname ? hosts[i].hostname : "");
        fprintf(fp, "\", \"status\": {\"discovered\": %s, \"up\": %s, \"reason\": \"",
                hosts[i].discovered ? "true" : "false",
                hosts[i].up ? "true" : "false");
        json_escape(fp, hosts[i].reason ? hosts[i].reason : "");
        fprintf(fp, "\"}, \"services\": [");

        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        for (uint32_t j = 0; j < service_count; j++)
        {
            if (j == 0)
                fprintf(fp, "\n");
            fprintf(fp, "      {\"port\": %u, \"proto\": \"%s\", \"service\": \"",
                    services[j].port,
                    services[j].proto);
            json_escape(fp, services[j].service);
            fprintf(fp, "\", \"state\": \"");
            json_escape(fp, services[j].state);
            fprintf(fp, "\", \"product\": \"");
            json_escape(fp, services[j].product);
            fprintf(fp, "\"");
            if (include_version)
            {
                fprintf(fp, ", \"version\": \"");
                json_escape(fp, services[j].version);
                fprintf(fp, "\"");
            }

            if (cfg->include_evidence)
            {
                np_evidence_view_t *evidence = NULL;
                uint32_t ec = np_query_evidence(ctx, services[j].node_id, &evidence);
                fprintf(fp, ", \"evidence\": [");
                for (uint32_t k = 0; k < ec; k++)
                {
                    if (k > 0)
                        fprintf(fp, ",");
                    fprintf(fp, "{\"source\": \"");
                    json_escape(fp, evidence[k].source);
                    fprintf(fp, "\", \"confidence\": %.3f}", evidence[k].confidence);
                }
                fprintf(fp, "]");
                np_query_free(evidence);
            }

            fprintf(fp, "}");
            if (j + 1 < service_count)
                fprintf(fp, ",");
            fprintf(fp, "\n");
        }

        uint32_t identified = np_recon_count_identified_services(services, service_count);
        np_query_free(services);

        np_os_view_t *oses = NULL;
        uint32_t os_count = 0;
        if (include_os)
            os_count = np_query_host_os(ctx, hosts[i].id, &oses);
        fprintf(fp, "    ]");
        if (include_os)
            fprintf(fp, ", \"os\": [");
        for (uint32_t j = 0; include_os && j < os_count; j++)
        {
            if (j > 0)
                fprintf(fp, ",");
            fprintf(fp, "{\"name\": \"");
            json_escape(fp, oses[j].name ? oses[j].name : "");
            fprintf(fp, "\", \"confidence\": %.3f}", oses[j].confidence);
        }
        np_query_free(oses);

        if (include_os)
            fprintf(fp, "], ");
        else
            fprintf(fp, ", ");

        fprintf(fp,
                "\"report_sections\": {"
                "\"target\": {\"hostname\": \"");
        json_escape(fp, hosts[i].hostname ? hosts[i].hostname : "");
        fprintf(fp, "\", \"ip\": \"");
        json_escape(fp, hosts[i].ip ? hosts[i].ip : "");
        fprintf(fp, "\"}, \"coverage\": {\"identified\": %u, \"total\": %u}}}",
                identified,
                service_count);
        if (i + 1 < host_count)
            fprintf(fp, ",");
        fprintf(fp, "\n");
    }

    np_query_free(hosts);
    fprintf(fp, "  ]\n}\n");

    if (fp != stdout)
        fclose(fp);
    return NP_OK;
}

const np_output_module_t np_recon_output_json_module = {
    .name = "recon.json",
    .format = "json",
    .extensions = "json",
    .emit = json_emit,
};
