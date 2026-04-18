#define _POSIX_C_SOURCE 200809L

#include "cli.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_privilege.h"
#include "core/error.h"
#include "logger.h"
#include "ports.h"
#include "route/route.h"
#include "target.h"

static void set_default_ports(np_port_spec_t *ports)
{
    ports->count = 0;
    for (uint32_t i = 0; i < np_top_ports_count; i++)
    {
        if (ports->count >= NP_MAX_PORT_RANGES)
            break;

        ports->ranges[ports->count].start = np_top_ports_top_1000[i];
        ports->ranges[ports->count].end = np_top_ports_top_1000[i];
        ports->count++;
    }
}

static void route_usage(void)
{
    fprintf(stderr,
            "Usage: netpeek route [options] <target>\n\n"
            "Options:\n"
            "  -p, --ports <spec>      Port specification (e.g. 22,80,443 or 1-1024)\n"
            "  -T, --threads <n>       Worker threads for hop scans\n"
            "      --timeout <ms>      Probe and connect timeout in milliseconds\n"
            "      --max-hops <n>      Maximum hop count\n"
            "  -o, --output <file>     Write report to file\n"
            "      --json              Write JSON output\n"
            "  -v, --verbose           Verbose logging + live graph\n"
            "  -h, --help              Show help\n");
}

int cmd_route(int argc, char **argv)
{
    np_route_options_t opts;
    memset(&opts, 0, sizeof(opts));

    opts.threads = NP_DEFAULT_THREADS;
    opts.timeout_ms = NP_DEFAULT_TIMEOUT;
    opts.max_hops = NP_MAX_TRACE_HOPS;
    set_default_ports(&opts.ports);

    static struct option long_opts[] = {
        {"ports", required_argument, NULL, 'p'},
        {"threads", required_argument, NULL, 'T'},
        {"timeout", required_argument, NULL, 1000},
        {"max-hops", required_argument, NULL, 1001},
        {"output", required_argument, NULL, 'o'},
        {"json", no_argument, NULL, 1002},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}};

    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    optreset = 1;
#endif

    int ch;
    while ((ch = getopt_long(argc, argv, "p:T:o:vh", long_opts, NULL)) != -1)
    {
        switch (ch)
        {
        case 'p':
            if (!np_parse_ports(optarg, &opts.ports) || np_ports_total(&opts.ports) == 0)
            {
                np_error(NP_ERR_RUNTIME, "[!] Invalid port specification: %s\n", optarg);
                return 2;
            }
            break;
        case 'T':
        {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 1024)
            {
                np_error(NP_ERR_RUNTIME, "[!] Invalid thread count: %s\n", optarg);
                return 2;
            }
            opts.threads = (uint32_t)v;
            break;
        }
        case 1000:
        {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 86400000ul)
            {
                np_error(NP_ERR_RUNTIME, "[!] Invalid timeout: %s\n", optarg);
                return 2;
            }
            opts.timeout_ms = (uint32_t)v;
            break;
        }
        case 1001:
        {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (!end || *end != '\0' || v < 1 || v > NP_MAX_TRACE_HOPS)
            {
                np_error(NP_ERR_RUNTIME, "[!] Invalid max hops: %s\n", optarg);
                return 2;
            }
            opts.max_hops = (uint32_t)v;
            break;
        }
        case 'o':
            opts.output_file = optarg;
            break;
        case 1002:
            opts.json_output = true;
            break;
        case 'v':
            opts.verbose = true;
            break;
        case 'h':
            route_usage();
            return 0;
        default:
            route_usage();
            return 2;
        }
    }

    if (optind >= argc)
    {
        route_usage();
        return 2;
    }

    opts.target = argv[optind];

    np_logger_init(NP_LOG_WARN, stderr);
    np_logger_set_verbose(opts.verbose);
    np_logger_set_level(opts.verbose ? NP_LOG_DEBUG : NP_LOG_WARN);

    if (!np_cli_require_root("route command", "Run with sudo: sudo netpeek route <target>"))
        return 3;

    if (opts.verbose)
    {
        LOGI("[route] target=%s threads=%u timeout=%ums max_hops=%u ports=%u\n",
             opts.target,
             opts.threads,
             opts.timeout_ms,
             opts.max_hops,
             np_ports_total(&opts.ports));
    }

    np_target_t target;
    memset(&target, 0, sizeof(target));
    strncpy(target.hostname, opts.target, sizeof(target.hostname) - 1);

    np_status_t rc = np_target_resolve(&target);
    if (rc != NP_OK)
    {
        np_error(NP_ERR_RUNTIME, "[!] Target resolution failed: %s\n", opts.target);
        return 3;
    }

    np_route_result_t result;
    rc = np_route_traceroute(&target, &opts, &result);
    if (rc != NP_OK)
    {
        np_error(NP_ERR_RUNTIME, "[!] Traceroute failed: %s\n", np_status_str(rc));
        return 4;
    }

    rc = np_route_scan_hops(&result, &opts);
    if (rc != NP_OK)
    {
        np_route_result_free(&result);
        np_error(NP_ERR_RUNTIME, "[!] Hop scan failed: %s\n", np_status_str(rc));
        return 4;
    }

    rc = np_route_write_output(&result, &opts);
    np_route_result_free(&result);

    if (rc != NP_OK)
    {
        np_error(NP_ERR_RUNTIME, "[!] Output failed: %s\n", np_status_str(rc));
        return 5;
    }

    return 0;
}
