#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"
#include "help.h"
#include "recon/diff.h"
#include "recon/output.h"

int cmd_diff(int argc, char **argv)
{
    int opt;
    const char *format = NULL;
    const char *out_path = NULL;
    bool no_color = false;

    static struct option long_opts[] = {
        {"json", no_argument, 0, 'j'},
        {"html", required_argument, 0, 1000},
        {"out", required_argument, 0, 1002},
        {"format", required_argument, 0, 1003},
        {"no-color", no_argument, 0, 1001},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

#if defined(__GLIBC__)
    optind = 0;
#else
    optind = 1;
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    optreset = 1;
#endif

    while ((opt = getopt_long(argc, argv, "jh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'j':
            format = "json";
            break;
        case 1000:
            format = "html";
            out_path = optarg;
            break;
        case 1002:
            out_path = optarg;
            break;
        case 1003:
            format = optarg;
            break;
        case 1001:
            no_color = true;
            break;
        case 'h':
            np_help_print_diff_usage("netpeek diff", stdout);
            return 0;
        default:
            np_help_print_diff_usage("netpeek diff", stderr);
            return 2;
        }
    }

    if (optind + 2 != argc)
    {
        np_help_print_diff_usage("netpeek diff", stderr);
        return 2;
    }

    if (!format)
    {
        if (out_path && out_path[0])
            format = np_format_from_extension(out_path);
        else
            format = "text";
    }

    bool use_color = !no_color && isatty(STDOUT_FILENO) == 1;
    return np_recon_diff_run(argv[optind], argv[optind + 1], format, out_path, use_color);
}
