#ifndef NP_CLI_H
#define NP_CLI_H

/**
 * Dispatch CLI subcommands.
 * Returns exit code.
 */
int np_cli_dispatch(int argc, char **argv);

/**
 * Subcommand: port scan
 */
int cmd_scan(int argc, char **argv);

/**
 * Subcommand: OS detection
 */
int cmd_os_detect(int argc, char **argv);

/**
 * Subcommand: NPE scripting engine runner
 */
int cmd_npe(int argc, char **argv);
int cmd_dns(int argc, char **argv);
int cmd_diff(int argc, char **argv);
int cmd_subenum(int argc, char **argv);
int cmd_recon(int argc, char **argv);
int cmd_route(int argc, char **argv);

/**
 * Print main help text.
 */
void cmd_help(void);

/**
 * Print version.
 */
void cmd_version(void);

#endif /* NP_CLI_H */
