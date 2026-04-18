#include <stdio.h>

#include "cli.h"
#include "help.h"

void cmd_help(void)
{
    np_help_print_overview("netpeek", stdout);
}
