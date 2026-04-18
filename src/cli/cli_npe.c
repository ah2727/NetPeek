#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdbool.h>
#include <getopt.h>

#include "cli.h"
#include "help.h"
#include "npe.h"
#include "npe/npe_loader.h"
#include "npe/npe_registry.h"
#include "npe/npe_script.h"
#include "logger.h"
#include "ui/style.h"

static void print_npe_help(const char *prog)
{
    np_help_print_npe_usage(prog, stdout);
}

static const char *guess_service_name(int port)
{
    switch (port)
    {
    case 80: return "http";
    case 443: return "https";
    case 22: return "ssh";
    case 53: return "dns";
    default: return NULL;
    }
}

static void print_run_header(const char *target, int port, const char *expr)
{
    FILE *fp = stdout;
    fprintf(fp, "\n%s%s%s %sScript Run%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, CLR_BRIGHT_CYAN), ICON_PROBE,
            np_clr(fp, CLR_WHITE), np_clr(fp, CLR_RESET));
    fprintf(fp, "  %sTarget:%s %s\n", np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), target);
    fprintf(fp, "  %sPort:%s   %d/tcp\n", np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), port);
    fprintf(fp, "  %sExpr:%s   %s\n", np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), expr);
}

static void print_live_step(const char *step)
{
    FILE *fp = stdout;
    fprintf(fp, "  %s%s%s %s\n",
            np_clr(fp, CLR_DIM), ICON_ARROW, np_clr(fp, CLR_RESET), step);
}

static char *trim_ws(char *s)
{
    if (!s)
        return s;

    while (*s && isspace((unsigned char)*s))
        s++;

    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';

    return s;
}

static int starts_with_ci(const char *s, const char *prefix)
{
    if (!s || !prefix)
        return 0;
    size_t n = strlen(prefix);
    return strncasecmp(s, prefix, n) == 0;
}

static void render_generic_result(const npe_result_entry_t *entry,
                                  const char *target,
                                  int port)
{
    FILE *fp = stdout;
    const char *script = entry->script_name[0] ? entry->script_name : "(unknown)";
    const char *status_icon = entry->result.status == NPE_OK ? ICON_CHECK : ICON_CROSS;
    const char *status_color = entry->result.status == NPE_OK ? CLR_BRIGHT_GREEN : CLR_BRIGHT_RED;

    fprintf(fp, "\n%s%s%s %s%s%s  %s(%s:%d/tcp)%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, status_color), status_icon,
            np_clr(fp, CLR_WHITE), script, np_clr(fp, CLR_RESET),
            np_clr(fp, CLR_DIM), target, port, np_clr(fp, CLR_RESET));

    fprintf(fp, "  %sElapsed:%s %.2f ms\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), entry->result.elapsed_ms);

    if (entry->result.output.type == NPE_VAL_STRING && entry->result.output.v.s)
    {
        fprintf(fp, "  %sOutput:%s\n", np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET));
        fprintf(fp, "    %s\n", entry->result.output.v.s);
    }
}

static void render_http_robots(const npe_result_entry_t *entry,
                               const char *target,
                               int port)
{
    FILE *fp = stdout;
    const char *raw = (entry->result.output.type == NPE_VAL_STRING && entry->result.output.v.s)
                          ? entry->result.output.v.s
                          : "";

    fprintf(fp, "\n%s%s%s %shttp-robots%s  %s(%s:%d/tcp)%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, CLR_BRIGHT_CYAN), ICON_NET,
            np_clr(fp, CLR_WHITE), np_clr(fp, CLR_RESET),
            np_clr(fp, CLR_DIM), target, port, np_clr(fp, CLR_RESET));

    fprintf(fp, "  %sElapsed:%s %.2f ms\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), entry->result.elapsed_ms);

    if (!raw[0])
    {
        fprintf(fp, "  %s%sNo robots data returned%s\n",
                np_clr(fp, CLR_BRIGHT_YELLOW), ICON_WARN, np_clr(fp, CLR_RESET));
        return;
    }

    if (starts_with_ci(raw, "ERROR:") || starts_with_ci(raw, "HTTP "))
    {
        fprintf(fp, "  %s%s %s%s\n",
                np_clr(fp, CLR_BRIGHT_RED), ICON_CROSS, raw, np_clr(fp, CLR_RESET));
        return;
    }

    size_t allow_count = 0;
    size_t disallow_count = 0;
    size_t sitemap_count = 0;
    size_t other_count = 0;

    char *dup = strdup(raw);
    if (!dup)
    {
        render_generic_result(entry, target, port);
        return;
    }

    fprintf(fp, "  %sDirectives:%s\n", np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET));

    char *saveptr = NULL;
    char *line = strtok_r(dup, "\n", &saveptr);
    while (line)
    {
        char *t = trim_ws(line);
        if (*t)
        {
            if (starts_with_ci(t, "allow:"))
            {
                allow_count++;
                fprintf(fp, "    %s•%s %s%s%s\n",
                        np_clr(fp, CLR_BRIGHT_GREEN), np_clr(fp, CLR_RESET),
                        np_clr(fp, CLR_BRIGHT_GREEN), t, np_clr(fp, CLR_RESET));
            }
            else if (starts_with_ci(t, "disallow:"))
            {
                disallow_count++;
                fprintf(fp, "    %s•%s %s%s%s\n",
                        np_clr(fp, CLR_BRIGHT_RED), np_clr(fp, CLR_RESET),
                        np_clr(fp, CLR_BRIGHT_RED), t, np_clr(fp, CLR_RESET));
            }
            else if (starts_with_ci(t, "sitemap:"))
            {
                sitemap_count++;
                fprintf(fp, "    %s•%s %s%s%s\n",
                        np_clr(fp, CLR_BRIGHT_CYAN), np_clr(fp, CLR_RESET),
                        np_clr(fp, CLR_BRIGHT_CYAN), t, np_clr(fp, CLR_RESET));
            }
            else
            {
                other_count++;
                fprintf(fp, "    • %s\n", t);
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(dup);

    fprintf(fp, "  %sSummary:%s allow=%zu disallow=%zu sitemap=%zu other=%zu\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET),
            allow_count, disallow_count, sitemap_count, other_count);
}

static void render_http_methods(const npe_result_entry_t *entry,
                                const char *target,
                                int port)
{
    FILE *fp = stdout;
    const char *raw = (entry->result.output.type == NPE_VAL_STRING && entry->result.output.v.s)
                          ? entry->result.output.v.s
                          : "";

    fprintf(fp, "\n%s%s%s %shttp-methods%s  %s(%s:%d/tcp)%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, CLR_BRIGHT_CYAN), ICON_NET,
            np_clr(fp, CLR_WHITE), np_clr(fp, CLR_RESET),
            np_clr(fp, CLR_DIM), target, port, np_clr(fp, CLR_RESET));

    fprintf(fp, "  %sElapsed:%s %.2f ms\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), entry->result.elapsed_ms);

    if (raw[0])
        fprintf(fp, "  %s\n", raw);
}

static void render_http_headers(const npe_result_entry_t *entry,
                                const char *target,
                                int port)
{
    FILE *fp = stdout;
    const char *raw = (entry->result.output.type == NPE_VAL_STRING && entry->result.output.v.s)
                          ? entry->result.output.v.s
                          : "";

    fprintf(fp, "\n%s%s%s %shttp-headers%s  %s(%s:%d/tcp)%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, CLR_BRIGHT_CYAN), ICON_NET,
            np_clr(fp, CLR_WHITE), np_clr(fp, CLR_RESET),
            np_clr(fp, CLR_DIM), target, port, np_clr(fp, CLR_RESET));

    fprintf(fp, "  %sElapsed:%s %.2f ms\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), entry->result.elapsed_ms);

    if (raw[0])
        fprintf(fp, "  %s\n", raw);
}

static void render_http_sitemap(const npe_result_entry_t *entry,
                                const char *target,
                                int port)
{
    FILE *fp = stdout;
    const char *raw = (entry->result.output.type == NPE_VAL_STRING && entry->result.output.v.s)
                          ? entry->result.output.v.s
                          : "";

    fprintf(fp, "\n%s%s%s %shttp-sitemap%s  %s(%s:%d/tcp)%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, CLR_BRIGHT_CYAN), ICON_NET,
            np_clr(fp, CLR_WHITE), np_clr(fp, CLR_RESET),
            np_clr(fp, CLR_DIM), target, port, np_clr(fp, CLR_RESET));

    fprintf(fp, "  %sElapsed:%s %.2f ms\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), entry->result.elapsed_ms);

    if (raw[0])
        fprintf(fp, "  %s\n", raw);
}

static void render_http_title(const npe_result_entry_t *entry,
                              const char *target,
                              int port)
{
    FILE *fp = stdout;
    const char *raw = (entry->result.output.type == NPE_VAL_STRING && entry->result.output.v.s)
                          ? entry->result.output.v.s
                          : "";

    fprintf(fp, "\n%s%s%s %shttp-title%s  %s(%s:%d/tcp)%s\n",
            np_clr(fp, CLR_BOLD), np_clr(fp, CLR_BRIGHT_CYAN), ICON_NET,
            np_clr(fp, CLR_WHITE), np_clr(fp, CLR_RESET),
            np_clr(fp, CLR_DIM), target, port, np_clr(fp, CLR_RESET));

    fprintf(fp, "  %sElapsed:%s %.2f ms\n",
            np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), entry->result.elapsed_ms);

    if (raw[0])
        fprintf(fp, "  %sTitle:%s %s\n",
                np_clr(fp, CLR_DIM), np_clr(fp, CLR_RESET), raw);
}

static void render_human_result(const npe_result_entry_t *entry,
                                const char *target,
                                int port)
{
    const char *script = entry->script_name;

    if (strcmp(script, "http-robots") == 0)
        render_http_robots(entry, target, port);
    else if (strcmp(script, "http-methods") == 0)
        render_http_methods(entry, target, port);
    else if (strcmp(script, "http-headers") == 0)
        render_http_headers(entry, target, port);
    else if (strcmp(script, "http-sitemap") == 0)
        render_http_sitemap(entry, target, port);
    else if (strcmp(script, "http-title") == 0)
        render_http_title(entry, target, port);
    else
        render_generic_result(entry, target, port);
}

static int run_target(const char *script_expr,
                      const char *target,
                      int port_number,
                      int use_json,
                      int verbose,
                      int script_threads)
{
    npe_engine_config_t config = {0};
    config.script_dir = "scripts";
    config.log_level = verbose ? NPE_LOG_DEBUG : NPE_LOG_WARN;
    config.thread_pool_size = (uint32_t)(script_threads > 0 ? script_threads : 4);
    config.default_timeout_ms = 30000;

    npe_engine_t *engine = NULL;
    npe_error_t err = npe_engine_create(&config, &engine);
    if (err != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Error creating NPE engine for %s: %d\n", target, err);
        return 1;
    }

    if (!use_json)
        print_run_header(target, port_number, script_expr);

    if (!use_json)
        print_live_step("Loading scripts");

    err = npe_engine_load_scripts(engine);
    if (err != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Error loading scripts for %s: %d\n", target, err);
        npe_engine_destroy(&engine);
        return 1;
    }

    if (!use_json)
        print_live_step("Selecting scripts");

    err = npe_engine_select_by_expression(engine, script_expr);
    if (err != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Error selecting scripts for %s: %d\n", target, err);
        npe_engine_destroy(&engine);
        return 1;
    }

    size_t selected = npe_engine_selected_count(engine);
    if (selected == 0)
    {
        np_error(NP_ERR_RUNTIME, "No scripts matched expression '%s'\n", script_expr);
        npe_engine_destroy(&engine);
        return 1;
    }

    npe_host_t host = {0};
    snprintf(host.ip, sizeof(host.ip), "%s", target);
    host.port_count = 1;
    host.ports = calloc(1, sizeof(npe_port_t));
    if (!host.ports)
    {
        np_error(NP_ERR_RUNTIME, "Memory allocation failed\n");
        npe_engine_destroy(&engine);
        return 1;
    }

    host.ports[0].number = (uint16_t)port_number;
    host.ports[0].protocol = NPE_PROTO_TCP;
    host.ports[0].state = NPE_PORT_OPEN;

    const char *svc = guess_service_name(port_number);
    if (svc)
        host.ports[0].service_name = strdup(svc);

    err = npe_engine_add_host(engine, &host);

    free(host.ports[0].service_name);
    free(host.ports);

    if (err != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Error adding host %s: %d\n", target, err);
        npe_engine_destroy(&engine);
        return 1;
    }

    if (!use_json)
        print_live_step("Executing scripts");

    err = npe_engine_run(engine);
    if (err != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Error running scripts on %s: %d\n", target, err);
        npe_engine_destroy(&engine);
        return 1;
    }

    npe_result_entry_t *entries = NULL;
    size_t entry_count = 0;
    err = npe_engine_get_result_entries(engine, &entries, &entry_count);
    if (err != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Error collecting results on %s: %d\n", target, err);
        npe_engine_destroy(&engine);
        return 1;
    }

    size_t ok_count = 0;
    size_t err_count = 0;
    size_t with_output_count = 0;

    for (size_t i = 0; i < entry_count; i++)
    {
        bool semantic_error = false;
        if (entries[i].result.output.type == NPE_VAL_STRING &&
            entries[i].result.output.v.s)
        {
            const char *out = entries[i].result.output.v.s;
            if (starts_with_ci(out, "ERROR:") ||
                starts_with_ci(out, "HTTP "))
                semantic_error = true;
        }

        if (entries[i].result.status == NPE_OK && !semantic_error)
            ok_count++;
        else
            err_count++;

        if (entries[i].result.output.type == NPE_VAL_STRING &&
            entries[i].result.output.v.s &&
            entries[i].result.output.v.s[0])
        {
            with_output_count++;
        }

        if (use_json)
        {
            char *line = npe_result_format_json(&entries[i]);
            if (line)
            {
                printf("%s\n", line);
                free(line);
            }
        }
        else
        {
            render_human_result(&entries[i], target, port_number);
        }
    }

    if (!use_json)
    {
        print_live_step("Completed");
        fprintf(stdout,
                "  %sSummary:%s total=%zu success=%zu error=%zu with_output=%zu\n",
                np_clr(stdout, CLR_DIM), np_clr(stdout, CLR_RESET),
                entry_count, ok_count, err_count, with_output_count);
    }

    for (size_t i = 0; i < entry_count; i++)
        npe_result_free_members(&entries[i].result);
    free(entries);

    npe_engine_destroy(&engine);
    return 0;
}

static int print_script_help_table(void)
{
    npe_loader_t *loader = NULL;
    npe_registry_t *registry = NULL;

    npe_loader_config_t lcfg = {
        .script_dir = "scripts",
        .script_db_path = "scripts/script.db",
        .recursive = true,
        .update_db = false,
        .log_level = NPE_LOG_ERROR,
    };

    if (npe_registry_create(&registry) != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Failed to create script registry\n");
        return 1;
    }

    if (npe_loader_create(&lcfg, &loader) != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Failed to create script loader\n");
        npe_registry_destroy(registry);
        return 1;
    }

    if (npe_loader_load_all(loader, registry) != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Failed to load scripts from scripts/\n");
        npe_loader_destroy(&loader);
        npe_registry_destroy(registry);
        return 1;
    }

    const npe_script_t **scripts = NULL;
    size_t count = 0;
    if (npe_registry_query_scripts(registry, NULL, &scripts, &count) != NPE_OK)
    {
        np_error(NP_ERR_RUNTIME, "Failed to query script metadata\n");
        npe_loader_destroy(&loader);
        npe_registry_destroy(registry);
        return 1;
    }

    printf("\n%-28s %-22s %-20s %s\n", "SCRIPT", "CATEGORIES", "DEPENDENCIES", "DESCRIPTION");
    printf("%-28s %-22s %-20s %s\n", "----------------------------", "----------------------", "--------------------", "-----------");

    for (size_t i = 0; i < count; i++)
    {
        const npe_script_t *s = scripts[i];
        char cat[256] = {0};
        char dep[256] = {0};

        npe_script_categories_str(s, cat, sizeof(cat));

        if (s->meta.dependency_count == 0)
        {
            snprintf(dep, sizeof(dep), "-");
        }
        else
        {
            size_t off = 0;
            for (size_t d = 0; d < s->meta.dependency_count; d++)
            {
                int n = snprintf(dep + off, sizeof(dep) - off, "%s%s",
                                 d == 0 ? "" : ",",
                                 s->meta.dependencies[d]);
                if (n <= 0 || (size_t)n >= sizeof(dep) - off)
                    break;
                off += (size_t)n;
            }
        }

        printf("%-28s %-22s %-20s %s\n",
               s->filename,
               cat[0] ? cat : "-",
               dep,
               s->meta.description[0] ? s->meta.description : "-");
    }

    npe_registry_free_query(scripts);
    npe_loader_destroy(&loader);
    npe_registry_destroy(registry);
    printf("\nUse --script with expressions like: \"safe and not brute\", \"default or vuln\", \"http-*\"\n");
    return 0;
}

int cmd_npe(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"script", required_argument, 0, 's'},
        {"script-help", no_argument, 0, 'H'},
        {"script-threads", required_argument, 0, 'T'},
        {"target", required_argument, 0, 't'},
        {"ports", required_argument, 0, 'p'},
        {"json", no_argument, 0, 'j'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    char *script_expr = NULL;
    char **targets = NULL;
    int target_count = 0;
    char *ports = "80";
    int show_help = 0;
    int use_json = 0;
    int verbose = 0;
    int script_threads = 4;

    int opt;
    while ((opt = getopt_long(argc, argv, "s:T:t:p:hjv", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 's':
            script_expr = optarg;
            break;
        case 'H':
            show_help = 1;
            break;
        case 'T':
            script_threads = atoi(optarg);
            if (script_threads <= 0)
            {
                np_error(NP_ERR_RUNTIME, "Error: --script-threads must be > 0\n");
                free(targets);
                return 1;
            }
            break;
        case 't':
            targets = realloc(targets, sizeof(char *) * (target_count + 1));
            if (!targets)
            {
                np_error(NP_ERR_RUNTIME, "Memory allocation failed\n");
                return 1;
            }
            targets[target_count++] = optarg;
            break;
        case 'p':
            ports = optarg;
            break;
        case 'j':
            use_json = 1;
            break;
        case 'v':
            verbose = 1;
            np_logger_set_verbose(true);
            break;
        case 'h':
            print_npe_help(argv[0]);
            free(targets);
            return 0;
        default:
            print_npe_help(argv[0]);
            free(targets);
            return 1;
        }
    }

    while (optind < argc)
    {
        char **new_targets = realloc(targets, sizeof(char *) * (target_count + 1));
        if (!new_targets)
        {
            np_error(NP_ERR_RUNTIME, "Memory allocation failed\n");
            free(targets);
            return 1;
        }
        targets = new_targets;
        targets[target_count++] = argv[optind++];
    }

    if (show_help)
    {
        int rc = print_script_help_table();
        free(targets);
        return rc;
    }

    if (!script_expr)
    {
        np_error(NP_ERR_RUNTIME, "Error: --script required\n");
        free(targets);
        return 1;
    }

    if (target_count == 0)
    {
        np_error(NP_ERR_RUNTIME, "Error: No targets specified\n");
        free(targets);
        return 1;
    }

    int port_number = atoi(ports);
    if (port_number <= 0 || port_number > 65535)
    {
        np_error(NP_ERR_RUNTIME, "Error: Invalid port '%s'\n", ports);
        free(targets);
        return 1;
    }

    int exit_code = 0;
    np_logger_set_level(verbose ? NP_LOG_DEBUG : NP_LOG_ERROR);
    for (int i = 0; i < target_count; i++)
    {
        int rc = run_target(script_expr, targets[i], port_number, use_json, verbose, script_threads);
        if (rc != 0)
            exit_code = rc;
    }

    free(targets);
    return exit_code;
}
