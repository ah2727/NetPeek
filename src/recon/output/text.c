#include "recon/output.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "recon/module.h"
#include "recon/port_table.h"
#include "recon/output_sections.h"
#include "recon/query.h"

#define C_RESET "\x1b[0m"
#define C_HOST "\x1b[36m"
#define C_IP "\x1b[36;2m"
#define C_PORT "\x1b[36m"
#define C_OPEN "\x1b[32m"
#define C_FILTERED "\x1b[33m"
#define C_CLOSED "\x1b[90m"
#define C_SERVICE "\x1b[34m"
#define C_VERSION "\x1b[35m"
#define C_OS "\x1b[95m"
#define C_EVIDENCE "\x1b[37;2m"

static bool text_use_color(FILE *fp, const np_output_config_t *cfg)
{
    if (!cfg->color)
        return false;
    return isatty(fileno(fp)) == 1;
}

static const char *c(bool enabled, const char *code)
{
    return enabled ? code : "";
}

static const char *state_title(const char *state)
{
    if (!state)
        return "Unknown";
    if (strcasecmp(state, "open") == 0)
        return "Open";
    if (strcasecmp(state, "open|filtered") == 0)
        return "Open|Filtered";
    if (strcasecmp(state, "filtered") == 0)
        return "Filtered";
    if (strcasecmp(state, "closed") == 0)
        return "Closed";
    return state;
}

static const char *state_color(const char *state)
{
    if (!state)
        return C_CLOSED;
    if (strcasecmp(state, "open") == 0)
        return C_OPEN;
    if (strcasecmp(state, "open|filtered") == 0 || strcasecmp(state, "filtered") == 0)
        return C_FILTERED;
    return C_CLOSED;
}

static void print_conf_bar(FILE *fp, double confidence)
{
    int pct = (int)(confidence * 100.0 + 0.5);
    if (pct < 0)
        pct = 0;
    if (pct > 100)
        pct = 100;

    int filled = (pct + 5) / 10;
    if (filled > 10)
        filled = 10;

    fputc('[', fp);
    for (int i = 0; i < filled; i++)
        fputs("█", fp);
    for (int i = filled; i < 10; i++)
        fputs("░", fp);
    fprintf(fp, "] %d%%", pct);
}

static void format_duration(time_t start_ts, char *buf, size_t len)
{
    time_t now = time(NULL);
    if (now < start_ts)
        now = start_ts;

    uint64_t elapsed = (uint64_t)(now - start_ts);
    unsigned mm = (unsigned)(elapsed / 60u);
    unsigned ss = (unsigned)(elapsed % 60u);
    snprintf(buf, len, "%02u:%02u", mm, ss);
}

typedef struct
{
    char name[96];
    uint32_t count;
} np_os_bucket_t;

typedef struct
{
    char name[160];
    uint32_t count;
} np_version_bucket_t;

static const char *module_stage_name(np_stage_t stage)
{
    switch (stage)
    {
    case NP_STAGE_DISCOVERY:
        return "discover";
    case NP_STAGE_ENUM:
        return "enum";
    case NP_STAGE_FINGERPRINT:
        return "fingerprint";
    case NP_STAGE_ENRICH:
        return "enrich";
    case NP_STAGE_ANALYZE:
        return "analyze";
    case NP_STAGE_REPORT:
        return "report";
    default:
        return "unknown";
    }
}

static const char *module_status_symbol(np_module_run_status_t status)
{
    switch (status)
    {
    case NP_MODULE_RUN_OK:
        return "✓";
    case NP_MODULE_RUN_FAILED:
        return "✗";
    case NP_MODULE_RUN_SKIPPED_DEP:
        return "↷";
    case NP_MODULE_RUN_SKIPPED_INTERRUPT:
        return "⊘";
    default:
        return "?";
    }
}

static void build_service_version_label(const np_service_view_t *svc,
                                        char *buf,
                                        size_t len)
{
    if (!buf || len == 0)
        return;

    buf[0] = '\0';
    if (!svc)
        return;

    if (svc->product && svc->product[0] && svc->version && svc->version[0])
    {
        snprintf(buf, len, "%s %s", svc->product, svc->version);
        return;
    }
    if (svc->version && svc->version[0])
    {
        snprintf(buf, len, "%s", svc->version);
        return;
    }
    if (svc->product && svc->product[0])
    {
        snprintf(buf, len, "%s", svc->product);
        return;
    }
}

static np_port_table_row_t *build_recon_port_rows(const np_service_view_t *services,
                                                  uint32_t service_count,
                                                  bool include_open_filtered,
                                                  uint32_t *row_count_out,
                                                  uint32_t *open_count_out,
                                                  uint32_t *open_filtered_count_out)
{
    if (!services)
        service_count = 0;

    uint32_t open_count = 0;
    uint32_t open_filtered_count = 0;

    for (uint32_t i = 0; i < service_count; i++)
    {
        const char *state = services[i].state && services[i].state[0] ? services[i].state : "unknown";
        if (strcasecmp(state, "open") == 0)
            open_count++;
        else if (include_open_filtered && strcasecmp(state, "open|filtered") == 0)
            open_filtered_count++;
    }

    uint32_t row_count = open_count + open_filtered_count;
    np_port_table_row_t *rows = NULL;
    if (row_count > 0)
        rows = calloc(row_count, sizeof(*rows));

    uint32_t idx = 0;
    for (int pass = 0; pass < 2; pass++)
    {
        for (uint32_t i = 0; i < service_count; i++)
        {
            const char *state = services[i].state && services[i].state[0] ? services[i].state : "unknown";
            bool is_open = strcasecmp(state, "open") == 0;
            bool is_open_filtered = include_open_filtered && strcasecmp(state, "open|filtered") == 0;

            if ((pass == 0 && !is_open) || (pass == 1 && !is_open_filtered))
                continue;
            if (!rows || idx >= row_count)
                continue;

            const char *proto = services[i].proto && services[i].proto[0] ? services[i].proto : "tcp";
            const char *svc = services[i].service && services[i].service[0] ? services[i].service : "unknown";

            snprintf(rows[idx].port, sizeof(rows[idx].port), "%u", services[i].port);
            snprintf(rows[idx].proto, sizeof(rows[idx].proto), "%s", proto);
            snprintf(rows[idx].service, sizeof(rows[idx].service), "%s", svc);
            snprintf(rows[idx].state, sizeof(rows[idx].state), "%s", state);
            build_service_version_label(&services[i], rows[idx].version, sizeof(rows[idx].version));
            idx++;
        }
    }

    if (row_count_out)
        *row_count_out = row_count;
    if (open_count_out)
        *open_count_out = open_count;
    if (open_filtered_count_out)
        *open_filtered_count_out = open_filtered_count;
    return rows;
}

static void render_analyze_graph(FILE *fp,
                                 np_recon_context_t *ctx,
                                 const np_output_config_t *cfg,
                                 np_host_view_t *hosts,
                                 uint32_t host_count)
{
    if (!ctx || !cfg)
        return;

    if (!ctx->cfg || !ctx->cfg->recon_subcommand || strcmp(ctx->cfg->recon_subcommand, "analyze") != 0)
        return;

    bool use_color = text_use_color(fp, cfg);

    fprintf(fp, "Analyze Graph:\n");

    np_module_run_record_t *runs = NULL;
    uint32_t run_count = np_module_last_run_snapshot(ctx, &runs);
    if (run_count > 0)
    {
        fprintf(fp, "  Stage Timeline:\n");
        for (uint32_t i = 0; i < run_count; i++)
        {
            uint64_t duration_ms = 0;
            if (runs[i].ended_ns > runs[i].started_ns)
                duration_ms = (runs[i].ended_ns - runs[i].started_ns) / 1000000ull;

            fprintf(fp,
                    "    %s %-11s %-24s %4llums\n",
                    module_status_symbol(runs[i].run_status),
                    module_stage_name(runs[i].stage),
                    runs[i].module_name,
                    (unsigned long long)duration_ms);
        }
    }
    else
    {
        fprintf(fp, "  Stage Timeline: unavailable\n");
    }
    np_module_run_snapshot_free(runs);

    if (!hosts || host_count == 0)
    {
        fprintf(fp, "  No host data available\n\n");
        return;
    }

    np_os_bucket_t buckets[32];
    np_version_bucket_t versions[32];
    memset(buckets, 0, sizeof(buckets));
    memset(versions, 0, sizeof(versions));
    uint32_t bucket_count = 0;
    uint32_t version_bucket_count = 0;
    uint32_t os_hosts = 0;
    uint32_t open_services = 0;
    uint32_t services_with_version = 0;

    for (uint32_t i = 0; i < host_count; i++)
    {
        np_service_view_t *services = NULL;
        uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
        open_services += service_count;

        for (uint32_t s = 0; s < service_count; s++)
        {
            char label[160];
            build_service_version_label(&services[s], label, sizeof(label));
            if (!label[0])
                continue;

            services_with_version++;
            bool matched_version = false;
            for (uint32_t v = 0; v < version_bucket_count; v++)
            {
                if (strcmp(versions[v].name, label) == 0)
                {
                    versions[v].count++;
                    matched_version = true;
                    break;
                }
            }

            if (!matched_version && version_bucket_count < (uint32_t)(sizeof(versions) / sizeof(versions[0])))
            {
                strncpy(versions[version_bucket_count].name, label,
                        sizeof(versions[version_bucket_count].name) - 1);
                versions[version_bucket_count].count = 1;
                version_bucket_count++;
            }
        }

        np_query_free(services);

        np_os_view_t *oses = NULL;
        uint32_t os_count = np_query_host_os(ctx, hosts[i].id, &oses);
        if (os_count == 0)
        {
            np_query_free(oses);
            continue;
        }

        const char *name = oses[0].name && oses[0].name[0] ? oses[0].name : "unknown";
        np_query_free(oses);
        os_hosts++;

        bool matched = false;
        for (uint32_t b = 0; b < bucket_count; b++)
        {
            if (strcmp(buckets[b].name, name) == 0)
            {
                buckets[b].count++;
                matched = true;
                break;
            }
        }

        if (!matched && bucket_count < (uint32_t)(sizeof(buckets) / sizeof(buckets[0])))
        {
            strncpy(buckets[bucket_count].name, name, sizeof(buckets[bucket_count].name) - 1);
            buckets[bucket_count].count = 1;
            bucket_count++;
        }

    }

    if (bucket_count > 0 && os_hosts > 0)
    {
        fprintf(fp, "  OS Distribution:\n");
        for (uint32_t b = 0; b < bucket_count; b++)
        {
            uint32_t pct = (buckets[b].count * 100u) / os_hosts;
            uint32_t filled = (buckets[b].count * 20u + os_hosts - 1u) / os_hosts;
            if (filled == 0)
                filled = 1;
            if (filled > 20)
                filled = 20;

            fprintf(fp, "    %s%-22s%s [",
                    c(use_color, C_OS),
                    buckets[b].name,
                    c(use_color, C_RESET));

            fprintf(fp, "%s", c(use_color, C_OPEN));
            for (uint32_t i = 0; i < filled; i++)
                fputs("█", fp);
            fprintf(fp, "%s", c(use_color, C_CLOSED));
            for (uint32_t i = filled; i < 20; i++)
                fputs("░", fp);
            fprintf(fp, "%s] %u%% (%u)\n",
                    c(use_color, C_RESET),
                    pct,
                    buckets[b].count);
        }
    }
    else
    {
        fprintf(fp, "  OS Distribution: none\n");
    }

    uint32_t version_pct = open_services ? (services_with_version * 100u) / open_services : 0;
    fprintf(fp,
            "  Service Version Coverage: %u/%u (%u%%)\n",
            services_with_version,
            open_services,
            version_pct);

    if (version_bucket_count > 0)
    {
        for (uint32_t i = 0; i + 1 < version_bucket_count; i++)
        {
            for (uint32_t j = i + 1; j < version_bucket_count; j++)
            {
                if (versions[j].count > versions[i].count)
                {
                    np_version_bucket_t tmp = versions[i];
                    versions[i] = versions[j];
                    versions[j] = tmp;
                }
            }
        }

        uint32_t top_n = version_bucket_count > 5 ? 5 : version_bucket_count;
        fprintf(fp, "  Top Service Versions:\n");
        for (uint32_t i = 0; i < top_n; i++)
            fprintf(fp, "    - %-36s %u\n", versions[i].name, versions[i].count);
    }
    else
    {
        fprintf(fp, "  Top Service Versions: none\n");
    }

    fputc('\n', fp);
}

static void print_evidence_block(FILE *fp,
                                 np_recon_context_t *ctx,
                                 const np_output_config_t *cfg,
                                 bool use_color,
                                 uint64_t node_id,
                                 const char *prefix,
                                 uint64_t *evidence_total)
{
    np_evidence_view_t *evidence = NULL;
    uint32_t ec = np_query_evidence(ctx, node_id, &evidence);
    *evidence_total += ec;

    if (ec == 0)
    {
        np_query_free(evidence);
        return;
    }

    if (!cfg->include_evidence && !cfg->verbose)
    {
        fprintf(fp, "%sEvidence: %u sources\n", prefix, ec);
        np_query_free(evidence);
        return;
    }

    fprintf(fp, "%sEvidence:\n", prefix);
    for (uint32_t i = 0; i < ec; i++)
    {
        fprintf(fp, "%s  %s%-16s%s confidence %.2f",
                prefix,
                c(use_color, C_EVIDENCE),
                evidence[i].source ? evidence[i].source : "unknown",
                c(use_color, C_RESET),
                evidence[i].confidence);
        if (evidence[i].description && evidence[i].description[0])
            fprintf(fp, " - %s", evidence[i].description);
        fputc('\n', fp);
    }

    np_query_free(evidence);
}

static uint32_t evidence_count_only(np_recon_context_t *ctx, uint64_t node_id)
{
    np_evidence_view_t *evidence = NULL;
    uint32_t ec = np_query_evidence(ctx, node_id, &evidence);
    np_query_free(evidence);
    return ec;
}

static void emit_classic_host(FILE *fp,
                              np_recon_context_t *ctx,
                              const np_output_config_t *cfg,
                              np_host_view_t *host,
                              uint64_t *total_services,
                              uint64_t *total_evidence)
{
    bool include_os = np_recon_should_show_os(ctx);
    const char *hostname = host->hostname && host->hostname[0] ? host->hostname : "unknown";
    const char *ip = host->ip && host->ip[0] ? host->ip : "unknown";
    const char *reason = host->reason && host->reason[0] ? host->reason : "no-reason";

    fprintf(fp, "NetPeek scan report for %s (%s)\n", hostname, ip);
    if (host->discovered)
    {
        fprintf(fp, "Host is %s (%s", host->up ? "up" : "down", reason);
        if (host->up && host->rtt_ms > 0.0)
            fprintf(fp, ", %.2fms", host->rtt_ms);
        fprintf(fp, ")\n");
    }

    np_service_view_t *services = NULL;
    uint32_t service_count = np_query_services(ctx, host->id, &services);
    *total_services += service_count;

    uint32_t table_row_count = 0;
    uint32_t open_count = 0;
    uint32_t open_filtered_count = 0;
    np_port_table_row_t *rows = build_recon_port_rows(services,
                                                      service_count,
                                                      !(ctx->cfg && ctx->cfg->drop_filtered_states),
                                                      &table_row_count,
                                                      &open_count,
                                                      &open_filtered_count);

    np_port_table_opts_t table_opts = {.indent = "", .force_ascii = !isatty(fileno(fp))};
    np_port_table_render(fp, rows, table_row_count, &table_opts);

    if (ctx->cfg && ctx->cfg->drop_filtered_states)
    {
        fprintf(fp, "confirmed open: %u\n", open_count);
    }
    else
    {
        fprintf(fp, "confirmed open: %u, uncertain open|filtered: %u\n",
                open_count,
                open_filtered_count);
        if (table_row_count > 0 && open_filtered_count > 0)
            fprintf(fp, "%u/%u ports are open|filtered (no reply; may be filtered)\n",
                    open_filtered_count,
                    table_row_count);
    }

    for (uint32_t j = 0; j < service_count; j++)
        print_evidence_block(fp, ctx, cfg, false, services[j].node_id, "  ", total_evidence);

    free(rows);

    if (include_os)
    {
        np_os_view_t *oses = NULL;
        uint32_t os_count = np_query_host_os(ctx, host->id, &oses);
        for (uint32_t j = 0; j < os_count; j++)
            fprintf(fp, "OS details: %s (confidence %.2f)\n", oses[j].name, oses[j].confidence);
        np_query_free(oses);
    }

    print_evidence_block(fp, ctx, cfg, false, host->id, "", total_evidence);
    fprintf(fp, "\n");

    np_query_free(services);
}

static void print_service_line(FILE *fp,
                               const np_output_config_t *cfg,
                               bool use_color,
                               const np_service_view_t *svc,
                               const char *prefix,
                               bool include_version)
{
    char port_proto[24] = {0};
    char version[192] = {0};
    const char *state = state_title(svc->state);

    snprintf(port_proto, sizeof(port_proto), "%u/%s", svc->port, svc->proto ? svc->proto : "tcp");

    if (svc->product && svc->product[0] && svc->version && svc->version[0])
        snprintf(version, sizeof(version), "%s %s", svc->product, svc->version);
    else if (svc->version && svc->version[0])
        snprintf(version, sizeof(version), "%s", svc->version);
    else if (svc->product && svc->product[0])
        snprintf(version, sizeof(version), "%s", svc->product);

    if (include_version)
    {
        fprintf(fp,
                "%s%s%-10s%s  %s%-10s%s  %s%-13s%s  %s%s%s",
                prefix,
                c(use_color, C_PORT),
                port_proto,
                c(use_color, C_RESET),
                c(use_color, C_SERVICE),
                svc->service ? svc->service : "unknown",
                c(use_color, C_RESET),
                c(use_color, state_color(svc->state)),
                state,
                c(use_color, C_RESET),
                c(use_color, C_VERSION),
                version[0] ? version : "-",
                c(use_color, C_RESET));
    }
    else
    {
        fprintf(fp,
                "%s%s%-10s%s  %s%-10s%s  %s%s%s",
                prefix,
                c(use_color, C_PORT),
                port_proto,
                c(use_color, C_RESET),
                c(use_color, C_SERVICE),
                svc->service ? svc->service : "unknown",
                c(use_color, C_RESET),
                c(use_color, state_color(svc->state)),
                state,
                c(use_color, C_RESET));
    }

    if (cfg->verbose && svc->tls_detected)
        fprintf(fp, "  tls");

    fputc('\n', fp);
}

static void emit_modern_host(FILE *fp,
                             np_recon_context_t *ctx,
                             const np_output_config_t *cfg,
                             np_host_view_t *host,
                             uint64_t *total_services,
                             uint64_t *total_evidence)
{
    bool include_version = np_recon_should_show_version(ctx);
    bool include_os = np_recon_should_show_os(ctx);
    bool use_color = text_use_color(fp, cfg);
    const char *hostname = host->hostname && host->hostname[0] ? host->hostname : "unknown";
    const char *ip = host->ip && host->ip[0] ? host->ip : "unknown";

    fprintf(fp,
            "%s●%s Host  %s%s%s  %s%s%s\n",
            c(use_color, C_HOST),
            c(use_color, C_RESET),
            c(use_color, C_HOST),
            hostname,
            c(use_color, C_RESET),
            c(use_color, C_IP),
            ip,
            c(use_color, C_RESET));

    np_os_view_t *oses = NULL;
    uint32_t os_count = 0;
    if (include_os)
        os_count = np_query_host_os(ctx, host->id, &oses);
    if (include_os && os_count > 0)
    {
        fprintf(fp, "  ├─ OS: %s%s%s   ", c(use_color, C_OS), oses[0].name, c(use_color, C_RESET));
        print_conf_bar(fp, oses[0].confidence);
        fputc('\n', fp);
    }
    np_query_free(oses);

    np_service_view_t *services = NULL;
    uint32_t service_count = np_query_services(ctx, host->id, &services);
    *total_services += service_count;

    if (!cfg->summary_only)
    {
        fprintf(fp, "  ├─ Services\n");
        if (service_count == 0)
        {
            fprintf(fp, "  │   none\n");
        }
        else
        {
            if (include_version)
                fprintf(fp, "  │   %-10s  %-10s  %-13s  %s\n",
                        "PORT/PROTO", "SERVICE", "STATE", "VERSION");
            else
                fprintf(fp, "  │   %-10s  %-10s  %s\n",
                        "PORT/PROTO", "SERVICE", "STATE");
            for (uint32_t j = 0; j < service_count; j++)
            {
                print_service_line(fp, cfg, use_color, &services[j], "  │   ", include_version);
                if (cfg->include_evidence || cfg->verbose)
                    print_evidence_block(fp, ctx, cfg, use_color, services[j].node_id, "  │     ", total_evidence);
                else
                    *total_evidence += evidence_count_only(ctx, services[j].node_id);
            }
        }
    }

    if (!cfg->summary_only)
    {
        if (cfg->include_evidence || cfg->verbose)
            fprintf(fp, "  └─ ");
        else
            fprintf(fp, "  └─ ");

        uint64_t before = *total_evidence;
        print_evidence_block(fp, ctx, cfg, use_color, host->id, "", total_evidence);
        if (*total_evidence == before)
            fprintf(fp, "Evidence: 0 sources\n");
    }

    np_query_free(services);
    fputc('\n', fp);
}

static void emit_redesigned_host(FILE *fp,
                                 np_recon_context_t *ctx,
                                 const np_output_config_t *cfg,
                                 np_host_view_t *host,
                                 uint64_t *total_services,
                                 uint64_t *total_evidence)
{
    bool include_os = np_recon_should_show_os(ctx);
    np_service_view_t *services = NULL;
    np_os_view_t *oses = NULL;
    uint32_t service_count = np_query_services(ctx, host->id, &services);
    uint32_t os_count = 0;
    if (include_os)
        os_count = np_query_host_os(ctx, host->id, &oses);
    uint32_t identified = np_recon_count_identified_services(services, service_count);
    uint32_t table_row_count = 0;
    uint32_t open_count = 0;
    uint32_t open_filtered_count = 0;

    *total_services += service_count;

    const char *hostname = host->hostname && host->hostname[0] ? host->hostname : "unknown";
    const char *ip = host->ip && host->ip[0] ? host->ip : "unknown";
    const char *os_name = (os_count > 0 && oses[0].name && oses[0].name[0]) ? oses[0].name : "Unknown";
    double os_conf = os_count > 0 ? oses[0].confidence : 0.0;
    int os_pct = (int)(os_conf * 100.0 + 0.5);

    fprintf(fp, "╭─────────────────────────────────────────────────────────────╮\n");
    fprintf(fp, "│ 🎯 Target: %s (%s)\n", hostname, ip);
    if (include_os)
    {
        fprintf(fp, "├─────────────────────────────────────────────────────────────┤\n");
        fprintf(fp, "│ 💻 OS: %s  Confidence: %d%%\n", os_name, os_pct);
    }
    fprintf(fp, "├─────────────────────────────────────────────────────────────┤\n");
    np_port_table_row_t *rows = build_recon_port_rows(services,
                                                      service_count,
                                                      !(ctx->cfg && ctx->cfg->drop_filtered_states),
                                                      &table_row_count,
                                                      &open_count,
                                                      &open_filtered_count);

    np_port_table_opts_t table_opts = {.indent = "│ ", .force_ascii = !isatty(fileno(fp))};
    np_port_table_render(fp, rows, table_row_count, &table_opts);

    for (uint32_t i = 0; i < service_count; i++)
        *total_evidence += evidence_count_only(ctx, services[i].node_id);

    if (service_count > 0)
    {
        if (ctx->cfg && ctx->cfg->drop_filtered_states)
            fprintf(fp, "│ ✓ confirmed open: %u\n", open_count);
        else
            fprintf(fp, "│ ✓ confirmed open: %u, uncertain open|filtered: %u\n",
                    open_count, open_filtered_count);
    }
    if (!(ctx->cfg && ctx->cfg->drop_filtered_states) && service_count > 0 && open_filtered_count > 0)
        fprintf(fp, "│ ⚠ %u/%u ports are open|filtered (no reply; may be filtered)\n",
                open_filtered_count, table_row_count);

    fprintf(fp, "├─────────────────────────────────────────────────────────────┤\n");
    fprintf(fp, "│ 📊 Coverage: %u/%u services identified", identified, service_count);
    if (service_count > 0)
        fprintf(fp, " (%u%%)", (identified * 100u) / service_count);
    else
        fprintf(fp, " (0%%)");
    fprintf(fp, "\n");
    fprintf(fp, "╰─────────────────────────────────────────────────────────────╯\n\n");

    free(rows);
    np_query_free(oses);
    np_query_free(services);
}

static np_status_t text_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
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
    uint64_t total_services = 0;
    uint64_t total_evidence = 0;

    fprintf(fp, "NetPeek recon report (run=%llu)\n\n",
            (unsigned long long)ctx->run_id);

    bool classic_mode = !cfg->recon_cli_mode || cfg->style == NP_RECON_STYLE_CLASSIC;
    for (uint32_t i = 0; i < host_count; i++)
    {
        if (cfg->summary_only)
            break;

        if (classic_mode)
            emit_classic_host(fp, ctx, cfg, &hosts[i], &total_services, &total_evidence);
        else
            emit_redesigned_host(fp, ctx, cfg, &hosts[i], &total_services, &total_evidence);
    }

    if (cfg->summary_only)
    {
        for (uint32_t i = 0; i < host_count; i++)
        {
            np_service_view_t *services = NULL;
            uint32_t service_count = np_query_services(ctx, hosts[i].id, &services);
            total_services += service_count;
            np_query_free(services);
        }
    }

    if (!classic_mode)
        render_analyze_graph(fp, ctx, cfg, hosts, host_count);

    char duration[32];
    format_duration(ctx->start_ts, duration, sizeof(duration));

    fprintf(fp, "────────────────────────────────────────────\n");
    fprintf(fp, "Hosts: %u   Services: %llu   New: 0   Changed: 0\n",
            host_count,
            (unsigned long long)total_services);
    fprintf(fp, "Duration: %s   Packets sent: %llu\n",
            duration,
            (unsigned long long)ctx->packets_sent);

    np_query_free(hosts);
    if (fp != stdout)
        fclose(fp);
    return NP_OK;
}

const np_output_module_t np_recon_output_text_module = {
    .name = "recon.text",
    .format = "text",
    .extensions = "txt log",
    .emit = text_emit,
};
