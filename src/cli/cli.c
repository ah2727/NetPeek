#include <stdio.h>
#include "core/error.h"
#include <string.h>
#include "args.h"
#include "cli.h"
#include "help.h"

int np_cli_dispatch(int argc, char **argv)
{
    if (argc < 2)
    {
        np_help_print_overview(argv[0], stdout);
        return 0;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0)
    {
        np_help_print_overview(argv[0], stdout);
        return 0;
    }

    if (strcmp(cmd, "help") == 0)
    {
        if (argc >= 3)
        {
            if (np_help_print_command_help(argv[2], argv[0], stdout))
                return 0;

            np_error(NP_ERR_RUNTIME, "Unknown command: %s\n\n", argv[2]);
            np_help_print_overview(argv[0], stderr);
            return 1;
        }

        np_help_print_overview(argv[0], stdout);
        return 0;
    }

    if (argc >= 3 && strcmp(argv[2], "help") == 0)
    {
        if (np_help_print_command_help(cmd, argv[0], stdout))
            return 0;
    }

    if (strcmp(cmd, "scan") == 0)
        return cmd_scan(argc - 1, &argv[1]);

    if (strcmp(cmd, "dns") == 0)
        return cmd_dns(argc - 1, &argv[1]);

    if (strcmp(cmd, "subenum") == 0 || strcmp(cmd, "subdomain") == 0 || strcmp(cmd, "sd") == 0)
        return cmd_subenum(argc - 1, &argv[1]);

    if (strcmp(cmd, "diff") == 0)
        return cmd_diff(argc - 1, &argv[1]);

    if (strcmp(cmd, "recon") == 0)
        return cmd_recon(argc - 1, &argv[1]);

    if (strcmp(cmd, "route") == 0)
        return cmd_route(argc - 1, &argv[1]);

    if (strcmp(cmd, "npe") == 0)
        return cmd_npe(argc - 1, &argv[1]);

    if (strcmp(cmd, "os-detect") == 0 || strcmp(cmd, "os") == 0)
        return cmd_os_detect(argc - 1, &argv[1]);

    if (strcmp(cmd, "version") == 0)
    {
        cmd_version();
        return 0;
    }

    np_error(NP_ERR_RUNTIME, "Unknown command: %s\n\n", cmd);
    np_help_print_overview(argv[0], stderr);
    return 1;
}
