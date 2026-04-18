#include "npe.h"
#include <stdlib.h>

void npe_table_free(npe_table_t **tbl)
{
    if (!tbl || !*tbl) return;
    if ((*tbl)->entries) {
        for (size_t i = 0; i < (*tbl)->count; i++) {
            free((*tbl)->entries[i].key);
            npe_value_free(&(*tbl)->entries[i].val);
        }
        free((*tbl)->entries);
    }
    
    free(*tbl);
    *tbl = NULL;
}
