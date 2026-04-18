#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "cli.h"
#include "cli_privilege.h"
#include "help.h"
#include "logger.h"
#include "recon/recon.h"
#include "recon/output.h"

static volatile sig_atomic_t interrupted = 0;

static void handle_sigint(int sig)
{
    (void)sig;
    interrupted = 1;
}

static void os_detect_usage(const char *prog)
{
    np_help_print_os_detect_usage(prog, stderr);
}

static int resolve_target(const char *host, char *out_ip, size_t out_ip_len)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return -1;

    int rc = -1;
    for (it = res; it; it = it->ai_next)
    {
        if (it->ai_family == AF_INET)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)it->ai_addr;
            if (inet_ntop(AF_INET, &addr->sin_addr, out_ip, out_ip_len))
            {
                rc = 0;
                break;
            }
        }
        else if (it->ai_family == AF_INET6)
        {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)it->ai_addr;
            if (inet_ntop(AF_INET6, &addr6->sin6_addr, out_ip, out_ip_len))
            {
                rc = 0;
                break;
            }
        }
    }

    freeaddrinfo(res);
    return rc;
}

int cmd_os_detect(int argc, char **argv)
{
    signal(SIGINT, handle_sigint);
    np_logger_init(NP_LOG_WARN, stderr);

    np_config_t *cfg = np_config_create();
    if (!cfg)
        return 1;

    const char *target = NULL;
    const char *sigfile = NULL;
    uint16_t port = 0;
    bool verbose = false;
    bool builtin_only = false;

    cfg->output_fmt = NP_OUTPUT_PLAIN;
    cfg->recon_cli_mode = true;
    cfg->recon_style = NP_RECON_STYLE_MODERN;
    cfg->recon_subcommand = "os-detect";

    static struct option long_opts[] = {
        {"target", required_argument, NULL, 't'},
        {"port", required_argument, NULL, 'p'},
        {"sigfile", required_argument, NULL, 's'},
        {"output", required_argument, NULL, 'o'},
        {"builtin", no_argument, NULL, 'B'},
        {"verbose", no_argument, NULL, 'v'},
        {"json", no_argument, NULL, 1000},
        {"csv", no_argument, NULL, 1001},
        {"osscan-guess", no_argument, NULL, 1002},
        {"osscan-limit", no_argument, NULL, 1003},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    optind = 1;
    int ch;

    while ((ch = getopt_long(argc, argv, "t:p:s:o:Bvh", long_opts, NULL)) != -1)
    {
        switch (ch)
        {
        case 't':
            target = optarg;
            break;
        case 'p':
            port = (uint16_t)atoi(optarg);
            break;
        case 's':
            sigfile = optarg;
            break;
        case 'o':
            cfg->output_file = optarg;
            break;
        case 'B':
            builtin_only = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 1000:
            cfg->output_fmt = NP_OUTPUT_JSON;
            break;
        case 1001:
            cfg->output_fmt = NP_OUTPUT_CSV;
            break;
        case 1002:
            cfg->osscan_guess = true;
            break;
        case 1003:
            cfg->osscan_limit = true;
            break;
        case 'h':
            os_detect_usage(argv[0]);
            np_config_destroy(cfg);
            return 0;
        default:
            os_detect_usage(argv[0]);
            np_config_destroy(cfg);
            return 1;
        }
    }

    if (!target && optind < argc)
        target = argv[optind];

    if (!target)
    {
        os_detect_usage(argv[0]);
        np_config_destroy(cfg);
        return 1;
    }

    if (!np_cli_require_root("os-detect command",
                             "Run with sudo: sudo netpeek os-detect -t <target>"))
    {
        np_config_destroy(cfg);
        return 1;
    }

    np_logger_set_verbose(verbose);
    np_logger_set_level(verbose ? NP_LOG_DEBUG : NP_LOG_WARN);

    char ip[INET6_ADDRSTRLEN];
    if (resolve_target(target, ip, sizeof(ip)) != 0)
    {
        np_error(NP_ERR_RUNTIME, "[!] Failed to resolve target: %s\n", target);
        np_config_destroy(cfg);
        return 1;
    }

    cfg->verbose = verbose;
    cfg->recon_verbose_detail = verbose;
    cfg->show_evidence = verbose;
    cfg->os_detect = true;
    cfg->os_builtin_only = builtin_only;
    cfg->os_target_port = port;
    cfg->os_target_input = target;
    cfg->os_sigfile_path = sigfile;

    np_status_t rc = np_recon_apply_legacy_output_mapping(cfg);
    if (rc != NP_OK)
    {
        np_config_destroy(cfg);
        return 1;
    }

    cfg->target_count = 1;
    cfg->targets = calloc(1, sizeof(np_target_t));
    if (!cfg->targets)
    {
        np_config_destroy(cfg);
        return 1;
    }

    np_target_t *tgt = &cfg->targets[0];
    strncpy(tgt->hostname, target, sizeof(tgt->hostname) - 1);
    strncpy(tgt->ip, ip, sizeof(tgt->ip) - 1);
    tgt->host_discovered = true;
    tgt->host_up = true;
    strncpy(tgt->host_reason, "os-detect", sizeof(tgt->host_reason) - 1);

    np_recon_context_t *ctx = np_recon_create(cfg);
    if (!ctx)
    {
        np_config_destroy(cfg);
        return 1;
    }

    rc = np_recon_register_builtin_modules(ctx);
    if (rc == NP_OK)
        rc = np_module_run_stage(ctx, NP_STAGE_FINGERPRINT);
    if (rc == NP_OK)
        rc = np_output_stage_run(ctx);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);

    if (rc != NP_OK)
    {
        if (interrupted)
            np_error(NP_ERR_RUNTIME, "\n[!] OS detect interrupted by user\n");
        return 1;
    }

    return 0;
}
