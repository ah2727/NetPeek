#include "npe.h"
#include "npe/npe_engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>


npe_error_t npe_quick_run(const npe_engine_config_t *config,
                          const char *script_expr,
                          const char *target_ip,
                          const npe_port_t *target_ports,
                          size_t port_count,
                          npe_result_t **results,
                          size_t *result_count)
{
    if (!script_expr || !target_ip || !results || !result_count)
        return NPE_ERROR_INVALID_ARG;

    *results      = NULL;
    *result_count = 0;

    npe_engine_t *engine = NULL;
    npe_error_t err = npe_engine_create(config, &engine);
    if (err != NPE_OK)
        return err;

    /* ---- load & select scripts BEFORE building the host ---- */

    err = npe_engine_load_scripts(engine);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    err = npe_engine_select_by_expression(engine, script_expr);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    /* ---- build host ---- */

    npe_host_t host = {0};
    strncpy(host.ip, target_ip, sizeof(host.ip) - 1);
    host.port_count = port_count;

    if (port_count > 0 && target_ports)
    {
        host.ports = malloc(sizeof(npe_port_t) * port_count);
        if (!host.ports)
        {
            npe_engine_destroy(&engine);
            return NPE_ERROR_NOMEM;
        }
        memcpy(host.ports, target_ports, sizeof(npe_port_t) * port_count);
    }

    /*
     * npe_engine_add_host copies the host data into its own storage,
     * so we free host.ports right after a successful add as well.
     */
    err = npe_engine_add_host(engine, &host);
    free(host.ports);          /* safe even if NULL */
    host.ports = NULL;

    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    /* ---- run ---- */

    err = npe_engine_run(engine);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    /* ---- collect results ---- */

    const npe_result_t *const_results = NULL;
    err = npe_engine_get_results(engine, &const_results, result_count);
    if (err == NPE_OK && *result_count > 0)
    {
        *results = malloc(sizeof(npe_result_t) * (*result_count));
        if (*results)
        {
            memcpy(*results, const_results, sizeof(npe_result_t) * (*result_count));
        }
        else
        {
            *result_count = 0;
            err = NPE_ERROR_NOMEM;
        }
    }

    npe_engine_destroy(&engine);
    return err;
}


void npe_value_free(npe_value_t *val)
{
    if (!val)
        return;

    switch (val->type)
    {
    case NPE_VAL_STRING:
        free(val->v.s);
        val->v.s = NULL;
        break;
    case NPE_VAL_BUFFER:
        if (val->v.buf)
        {
            free(val->v.buf->data);
            free(val->v.buf);
            val->v.buf = NULL;
        }
        break;
    case NPE_VAL_TABLE:
        npe_table_free(&val->v.tbl);
        break;
    default:
        break;
    }
    val->type = NPE_VAL_NIL;
}
