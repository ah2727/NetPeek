#include "recon/output.h"

#include <stdio.h>

#include "recon/output_sections.h"
#include "recon/query.h"

static void html_escape(FILE *fp, const char *s)
{
    if (!s)
        return;

    while (*s)
    {
        switch (*s)
        {
        case '&': fputs("&amp;", fp); break;
        case '<': fputs("&lt;", fp); break;
        case '>': fputs("&gt;", fp); break;
        case '"': fputs("&quot;", fp); break;
        default: fputc(*s, fp); break;
        }
        s++;
    }
}

static np_status_t html_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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

    fprintf(fp,
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>NetPeek Recon Report</title>"
            "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;margin:18px;background:#0f172a;color:#e2e8f0;}"
            "h1,h2{margin:.2em 0;}details{background:#111827;border:1px solid #1f2937;border-radius:8px;margin:10px 0;padding:8px;}"
            "summary{cursor:pointer;font-weight:600;}"
            "table{border-collapse:collapse;width:100%%;margin-top:8px;}th,td{border:1px solid #334155;padding:6px 8px;text-align:left;font-size:13px;}"
            "th{background:#1e293b;}"
            "small{color:#94a3b8;}"
            "</style></head><body>");

    fprintf(fp, "<h1>NetPeek Recon Report</h1>");
    fprintf(fp, "<small>run=%llu, hosts=%u</small>",
            (unsigned long long)ctx->run_id,
            host_count);

    for (uint32_t i = 0; i < host_count; i++)
    {
        const char *hostname = hosts[i].hostname && hosts[i].hostname[0] ? hosts[i].hostname : "unknown";
        const char *ip = hosts[i].ip && hosts[i].ip[0] ? hosts[i].ip : "unknown";

        fprintf(fp, "<details open><summary>");
        html_escape(fp, hostname);
        fprintf(fp, " (");
        html_escape(fp, ip);
        fprintf(fp, ")</summary>");

        np_os_view_t *oses = NULL;
        uint32_t os_count = np_query_host_os(ctx, hosts[i].id, &oses);
        if (include_os && os_count > 0)
        {
            fprintf(fp, "<p><strong>OS:</strong> ");
            html_escape(fp, oses[0].name);
            fprintf(fp, " (%.0f%%)</p>", oses[0].confidence * 100.0);
        }
        np_query_free(oses);

        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        uint32_t identified = np_recon_count_identified_services(services, service_count);

        if (service_count == 0)
        {
            fprintf(fp, "<p>No open services discovered</p>");
        }
        else
        {
            if (include_version)
                fprintf(fp, "<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>State</th><th>Version</th></tr></thead><tbody>");
            else
                fprintf(fp, "<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>State</th></tr></thead><tbody>");
            for (uint32_t j = 0; j < service_count; j++)
            {
                fprintf(fp, "<tr><td>%u</td><td>", services[j].port);
                html_escape(fp, services[j].proto);
                fprintf(fp, "</td><td>");
                html_escape(fp, services[j].service);
                fprintf(fp, "</td><td>");
                html_escape(fp, services[j].state);
                if (include_version)
                {
                    fprintf(fp, "</td><td>");
                    html_escape(fp, services[j].version);
                }
                fprintf(fp, "</td></tr>");
            }
            fprintf(fp, "</tbody></table>");
        }

        fprintf(fp, "<section><h3>Report Sections</h3>");
        fprintf(fp, "<p><strong>Coverage:</strong> %u/%u services identified</p>", identified, service_count);
        fprintf(fp, "</section>");

        np_query_free(services);
        fprintf(fp, "</details>");
    }

    np_query_free(hosts);

    fprintf(fp, "</body></html>\n");
    if (fp != stdout)
        fclose(fp);

    return NP_OK;
}

const np_output_module_t np_recon_output_html_module = {
    .name = "recon.html",
    .format = "html",
    .extensions = "html htm",
    .emit = html_emit,
};
