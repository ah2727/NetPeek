#ifndef NP_PORT_TABLE_H
#define NP_PORT_TABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    char port[16];
    char proto[8];
    char service[128];
    char state[16];
    char version[160];
} np_port_table_row_t;

typedef struct {
    const char *indent;
    bool force_ascii;
} np_port_table_opts_t;

void np_port_table_render(FILE *fp,
                          const np_port_table_row_t *rows,
                          uint32_t row_count,
                          const np_port_table_opts_t *opts);

#endif
