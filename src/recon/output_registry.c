#include "recon/output.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    const np_output_module_t **items;
    size_t count;
    size_t cap;
} np_output_registry_t;

static np_output_registry_t g_registry;

static bool reserve_registry(void)
{
    if (g_registry.count < g_registry.cap)
        return true;

    size_t next_cap = g_registry.cap ? g_registry.cap * 2 : 8;
    const np_output_module_t **next = realloc(g_registry.items,
                                              next_cap * sizeof(*next));
    if (!next)
        return false;

    g_registry.items = next;
    g_registry.cap = next_cap;
    return true;
}

np_status_t np_output_register(const np_output_module_t *module)
{
    if (!module || !module->format || !module->emit)
        return NP_ERR_ARGS;

    for (size_t i = 0; i < g_registry.count; i++)
    {
        if (strcasecmp(g_registry.items[i]->format, module->format) == 0)
            return NP_OK;
    }

    if (!reserve_registry())
        return NP_ERR_MEMORY;

    g_registry.items[g_registry.count++] = module;
    return NP_OK;
}

const np_output_module_t *np_output_find(const char *format)
{
    if (!format)
        return NULL;

    for (size_t i = 0; i < g_registry.count; i++)
    {
        if (strcasecmp(g_registry.items[i]->format, format) == 0)
            return g_registry.items[i];
    }

    return NULL;
}

const char *np_format_from_extension(const char *filename)
{
    if (!filename)
        return "text";

    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "text";

    dot++;

    if (strcasecmp(dot, "txt") == 0 || strcasecmp(dot, "log") == 0)
        return "text";
    if (strcasecmp(dot, "json") == 0)
        return "json";
    if (strcasecmp(dot, "csv") == 0)
        return "csv";
    if (strcasecmp(dot, "md") == 0 || strcasecmp(dot, "markdown") == 0)
        return "md";
    if (strcasecmp(dot, "html") == 0 || strcasecmp(dot, "htm") == 0)
        return "html";
    if (strcasecmp(dot, "xml") == 0)
        return "xml";
    if (strcasecmp(dot, "sarif") == 0)
        return "sarif";
    if (strcasecmp(dot, "diff") == 0 || strcasecmp(dot, "patch") == 0)
        return "diff";

    return "text";
}
