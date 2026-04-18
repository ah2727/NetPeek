#ifndef NP_HELP_H
#define NP_HELP_H

#include <stdbool.h>
#include <stdio.h>

const char *np_help_resolve_command(const char *name);

void np_help_print_overview(const char *prog, FILE *out);
void np_help_print_scan_usage(const char *prog, FILE *out);
void np_help_print_npe_usage(const char *prog, FILE *out);
void np_help_print_os_detect_usage(const char *prog, FILE *out);
void np_help_print_dns_usage(const char *prog, FILE *out);
void np_help_print_subenum_usage(const char *prog, FILE *out);
void np_help_print_diff_usage(const char *prog, FILE *out);
void np_help_print_recon_usage(const char *prog, FILE *out);
void np_help_print_route_usage(const char *prog, FILE *out);
bool np_help_print_command_help(const char *command, const char *prog, FILE *out);

#endif
