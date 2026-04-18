#include "recon/diff.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "npe_lib/npe_lib_json.h"

#define C_RESET "\x1b[0m"
#define C_ADD "\x1b[92m"
#define C_REMOVE "\x1b[31m"
#define C_CHANGE "\x1b[33;1m"

typedef struct
{
    uint16_t port;
    char *proto;
    char *service;
    char *state;
    char *version;
} np_recon_diff_service_t;

typedef struct
{
    char *key;
    char *label;
    np_recon_diff_service_t *services;
    size_t service_count;
} np_recon_diff_host_t;

typedef struct
{
    np_recon_diff_host_t *hosts;
    size_t host_count;
} np_recon_diff_scan_t;

static char *np_strdup(const char *value)
{
    if (!value)
        value = "";

    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (!copy)
        return NULL;

    memcpy(copy, value, len);
    return copy;
}

static int read_file(const char *path, char **buf, size_t *len)
{
    *buf = NULL;
    *len = 0;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return -1;
    }

    long size = ftell(fp);
    if (size < 0)
    {
        fclose(fp);
        return -1;
    }

    rewind(fp);

    char *tmp = malloc((size_t)size + 1);
    if (!tmp)
    {
        fclose(fp);
        return -1;
    }

    size_t n = fread(tmp, 1, (size_t)size, fp);
    fclose(fp);
    tmp[n] = '\0';

    *buf = tmp;
    *len = n;
    return 0;
}

static npe_json_value_t *json_obj_get(npe_json_value_t *obj, const char *key)
{
    if (!obj || obj->type != NPE_JSON_OBJECT || !key)
        return NULL;

    for (size_t i = 0; i < obj->object.count; i++)
    {
        if (obj->object.keys[i] && strcmp(obj->object.keys[i], key) == 0)
            return obj->object.values[i];
    }

    return NULL;
}

static const char *json_str(npe_json_value_t *obj, const char *key)
{
    npe_json_value_t *value = json_obj_get(obj, key);
    if (!value || value->type != NPE_JSON_STRING || !value->string)
        return "";

    return value->string;
}

static uint16_t json_u16(npe_json_value_t *obj, const char *key)
{
    npe_json_value_t *value = json_obj_get(obj, key);
    if (!value || value->type != NPE_JSON_NUMBER)
        return 0;

    if (value->number < 0)
        return 0;
    if (value->number > 65535)
        return 65535;

    return (uint16_t)value->number;
}

static int parse_scan(const char *path, np_recon_diff_scan_t *out)
{
    memset(out, 0, sizeof(*out));

    char *content = NULL;
    size_t content_len = 0;
    if (read_file(path, &content, &content_len) != 0)
    {
        fprintf(stderr, "[recon-diff] failed to read file: %s\n", path);
        return -1;
    }

    npe_json_value_t *root = NULL;
    if (npe_json_parse(content, content_len, &root) != NPE_OK || !root)
    {
        fprintf(stderr, "[recon-diff] invalid JSON: %s\n", path);
        free(content);
        return -1;
    }
    free(content);

    npe_json_value_t *hosts = json_obj_get(root, "hosts");
    if (!hosts || hosts->type != NPE_JSON_ARRAY)
    {
        fprintf(stderr, "[recon-diff] missing hosts[] array: %s\n", path);
        npe_json_free(root);
        return -1;
    }

    out->hosts = calloc(hosts->array.count, sizeof(np_recon_diff_host_t));
    if (!out->hosts)
    {
        npe_json_free(root);
        return -1;
    }

    for (size_t i = 0; i < hosts->array.count; i++)
    {
        npe_json_value_t *host_obj = hosts->array.items[i];
        if (!host_obj || host_obj->type != NPE_JSON_OBJECT)
            continue;

        np_recon_diff_host_t *host = &out->hosts[out->host_count++];
        const char *ip = json_str(host_obj, "ip");
        const char *hostname = json_str(host_obj, "hostname");

        host->key = np_strdup(ip[0] ? ip : hostname);

        if (hostname[0] && ip[0])
        {
            size_t n = strlen(hostname) + strlen(ip) + 4;
            host->label = malloc(n);
            if (host->label)
                snprintf(host->label, n, "%s (%s)", hostname, ip);
        }
        else
        {
            host->label = np_strdup(host->key ? host->key : "unknown");
        }

        npe_json_value_t *services = json_obj_get(host_obj, "services");
        if (!services || services->type != NPE_JSON_ARRAY)
            continue;

        host->services = calloc(services->array.count, sizeof(np_recon_diff_service_t));
        if (!host->services)
            continue;

        for (size_t j = 0; j < services->array.count; j++)
        {
            npe_json_value_t *svc = services->array.items[j];
            if (!svc || svc->type != NPE_JSON_OBJECT)
                continue;

            np_recon_diff_service_t *dst = &host->services[host->service_count++];
            dst->port = json_u16(svc, "port");
            dst->proto = np_strdup(json_str(svc, "proto"));
            dst->service = np_strdup(json_str(svc, "service"));
            dst->state = np_strdup(json_str(svc, "state"));

            const char *product = json_str(svc, "product");
            const char *version = json_str(svc, "version");
            if (product[0] && version[0])
            {
                size_t n = strlen(product) + strlen(version) + 2;
                dst->version = malloc(n);
                if (dst->version)
                    snprintf(dst->version, n, "%s %s", product, version);
            }
            else if (version[0])
            {
                dst->version = np_strdup(version);
            }
            else
            {
                dst->version = np_strdup(product);
            }
        }
    }

    npe_json_free(root);
    return 0;
}

static void free_scan(np_recon_diff_scan_t *scan)
{
    if (!scan)
        return;

    for (size_t i = 0; i < scan->host_count; i++)
    {
        np_recon_diff_host_t *host = &scan->hosts[i];
        free(host->key);
        free(host->label);

        for (size_t j = 0; j < host->service_count; j++)
        {
            free(host->services[j].proto);
            free(host->services[j].service);
            free(host->services[j].state);
            free(host->services[j].version);
        }

        free(host->services);
    }

    free(scan->hosts);
    memset(scan, 0, sizeof(*scan));
}

static np_recon_diff_host_t *find_host(np_recon_diff_scan_t *scan, const char *key)
{
    for (size_t i = 0; i < scan->host_count; i++)
    {
        if (scan->hosts[i].key && strcmp(scan->hosts[i].key, key) == 0)
            return &scan->hosts[i];
    }

    return NULL;
}

static np_recon_diff_service_t *find_service(np_recon_diff_host_t *host, uint16_t port, const char *proto)
{
    for (size_t i = 0; i < host->service_count; i++)
    {
        if (host->services[i].port == port && strcmp(host->services[i].proto ? host->services[i].proto : "", proto ? proto : "") == 0)
            return &host->services[i];
    }

    return NULL;
}

static const char *cc(bool enabled, const char *value)
{
    return enabled ? value : "";
}

static void print_text(FILE *fp,
                       np_recon_diff_scan_t *old_scan,
                       np_recon_diff_scan_t *new_scan,
                       bool use_color,
                       const char *old_name,
                       const char *new_name)
{
    fprintf(fp, "▶ Recon Diff (%s → %s)\n\n", old_name, new_name);
    fprintf(fp, "Legend: %s+ Added%s   %s~ Changed%s   %s- Removed%s\n\n",
            cc(use_color, C_ADD), cc(use_color, C_RESET),
            cc(use_color, C_CHANGE), cc(use_color, C_RESET),
            cc(use_color, C_REMOVE), cc(use_color, C_RESET));

    for (size_t i = 0; i < new_scan->host_count; i++)
    {
        np_recon_diff_host_t *new_host = &new_scan->hosts[i];
        np_recon_diff_host_t *old_host = find_host(old_scan, new_host->key ? new_host->key : "");

        if (!old_host)
        {
            fprintf(fp, "%s+ %s%s\n", cc(use_color, C_ADD), new_host->label ? new_host->label : "unknown", cc(use_color, C_RESET));
            for (size_t j = 0; j < new_host->service_count; j++)
            {
                fprintf(fp,
                        "    %s+ %u/%s  %s  %s%s\n",
                        cc(use_color, C_ADD),
                        new_host->services[j].port,
                        new_host->services[j].proto ? new_host->services[j].proto : "tcp",
                        new_host->services[j].service ? new_host->services[j].service : "unknown",
                        new_host->services[j].state ? new_host->services[j].state : "unknown",
                        cc(use_color, C_RESET));
            }
            fprintf(fp, "\n");
            continue;
        }

        bool host_changed = false;
        for (size_t j = 0; j < new_host->service_count; j++)
        {
            np_recon_diff_service_t *new_service = &new_host->services[j];
            np_recon_diff_service_t *old_service = find_service(old_host, new_service->port, new_service->proto);

            if (!old_service)
            {
                if (!host_changed)
                {
                    fprintf(fp, "%s~ %s%s\n", cc(use_color, C_CHANGE), new_host->label ? new_host->label : "unknown", cc(use_color, C_RESET));
                    host_changed = true;
                }
                fprintf(fp,
                        "    %s+ %u/%s  %s  %s%s\n",
                        cc(use_color, C_ADD),
                        new_service->port,
                        new_service->proto ? new_service->proto : "tcp",
                        new_service->service ? new_service->service : "unknown",
                        new_service->state ? new_service->state : "unknown",
                        cc(use_color, C_RESET));
                continue;
            }

            const char *old_version = old_service->version ? old_service->version : "";
            const char *new_version = new_service->version ? new_service->version : "";
            if (strcmp(old_version, new_version) != 0)
            {
                if (!host_changed)
                {
                    fprintf(fp, "%s~ %s%s\n", cc(use_color, C_CHANGE), new_host->label ? new_host->label : "unknown", cc(use_color, C_RESET));
                    host_changed = true;
                }
                fprintf(fp,
                        "    %s~ %u/%s version %s → %s%s\n",
                        cc(use_color, C_CHANGE),
                        new_service->port,
                        new_service->proto ? new_service->proto : "tcp",
                        old_version[0] ? old_version : "(none)",
                        new_version[0] ? new_version : "(none)",
                        cc(use_color, C_RESET));
            }
        }

        for (size_t j = 0; j < old_host->service_count; j++)
        {
            np_recon_diff_service_t *old_service = &old_host->services[j];
            np_recon_diff_service_t *new_service = find_service(new_host, old_service->port, old_service->proto);
            if (!new_service)
            {
                if (!host_changed)
                {
                    fprintf(fp, "%s~ %s%s\n", cc(use_color, C_CHANGE), new_host->label ? new_host->label : "unknown", cc(use_color, C_RESET));
                    host_changed = true;
                }
                fprintf(fp,
                        "    %s- %u/%s  %s%s\n",
                        cc(use_color, C_REMOVE),
                        old_service->port,
                        old_service->proto ? old_service->proto : "tcp",
                        old_service->service ? old_service->service : "unknown",
                        cc(use_color, C_RESET));
            }
        }

        if (host_changed)
            fprintf(fp, "\n");
    }

    for (size_t i = 0; i < old_scan->host_count; i++)
    {
        np_recon_diff_host_t *old_host = &old_scan->hosts[i];
        if (find_host(new_scan, old_host->key ? old_host->key : ""))
            continue;

        fprintf(fp, "%s- %s%s\n", cc(use_color, C_REMOVE), old_host->label ? old_host->label : "unknown", cc(use_color, C_RESET));
        for (size_t j = 0; j < old_host->service_count; j++)
        {
            fprintf(fp,
                    "    %s- %u/%s  %s%s\n",
                    cc(use_color, C_REMOVE),
                    old_host->services[j].port,
                    old_host->services[j].proto ? old_host->services[j].proto : "tcp",
                    old_host->services[j].service ? old_host->services[j].service : "unknown",
                    cc(use_color, C_RESET));
        }
        fprintf(fp, "\n");
    }
}

static void print_json(FILE *fp, np_recon_diff_scan_t *old_scan, np_recon_diff_scan_t *new_scan)
{
    fprintf(fp,
            "{\n"
            "  \"format\": \"recon-diff\",\n"
            "  \"old_hosts\": %zu,\n"
            "  \"new_hosts\": %zu\n"
            "}\n",
            old_scan->host_count,
            new_scan->host_count);
}

static void print_md(FILE *fp, np_recon_diff_scan_t *old_scan, np_recon_diff_scan_t *new_scan, const char *old_name, const char *new_name)
{
    fprintf(fp, "# NetPeek Recon Diff\n\n");
    fprintf(fp, "- Old: `%s`\n", old_name);
    fprintf(fp, "- New: `%s`\n", new_name);
    fprintf(fp, "- Old hosts: `%zu`\n", old_scan->host_count);
    fprintf(fp, "- New hosts: `%zu`\n", new_scan->host_count);
    fprintf(fp, "\nUse `--format text` for line-level changes.\n");
}

static void print_xml(FILE *fp, np_recon_diff_scan_t *old_scan, np_recon_diff_scan_t *new_scan, const char *old_name, const char *new_name)
{
    fprintf(fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<reconDiff old=\"%s\" new=\"%s\" oldHosts=\"%zu\" newHosts=\"%zu\"/>\n",
            old_name,
            new_name,
            old_scan->host_count,
            new_scan->host_count);
}

static void print_sarif(FILE *fp)
{
    fprintf(fp,
            "{\n"
            "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n"
            "  \"version\": \"2.1.0\",\n"
            "  \"runs\": [{\n"
            "    \"tool\": {\"driver\": {\"name\": \"NetPeek Recon Diff\"}},\n"
            "    \"results\": []\n"
            "  }]\n"
            "}\n");
}

static void print_html(FILE *fp, np_recon_diff_scan_t *old_scan, np_recon_diff_scan_t *new_scan, const char *old_name, const char *new_name)
{
    fprintf(fp,
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Recon Diff</title>"
            "<style>body{font-family:Arial,sans-serif;margin:18px;background:#0f172a;color:#e2e8f0;}"
            "table{border-collapse:collapse;width:100%%;}th,td{border:1px solid #334155;padding:6px;}"
            "th{background:#1e293b;}h1,h2{margin:.3em 0;}</style></head><body>");
    fprintf(fp, "<h1>Recon Diff</h1><p>%s → %s</p>", old_name, new_name);
    fprintf(fp,
            "<h2>Host Counts</h2><table><tr><th>Old Hosts</th><th>New Hosts</th></tr><tr><td>%zu</td><td>%zu</td></tr></table>",
            old_scan->host_count,
            new_scan->host_count);
    fputs("</body></html>\n", fp);
}

int np_recon_diff_run(const char *old_path,
                      const char *new_path,
                      const char *format,
                      const char *out_path,
                      bool use_color)
{
    np_recon_diff_scan_t old_scan;
    np_recon_diff_scan_t new_scan;

    if (parse_scan(old_path, &old_scan) != 0)
        return 1;

    if (parse_scan(new_path, &new_scan) != 0)
    {
        free_scan(&old_scan);
        return 1;
    }

    const char *resolved_format = (format && format[0]) ? format : "text";
    FILE *fp = stdout;
    if (out_path && out_path[0])
    {
        fp = fopen(out_path, "w");
        if (!fp)
        {
            fprintf(stderr, "[recon-diff] cannot open output %s: %s\n", out_path, strerror(errno));
            free_scan(&old_scan);
            free_scan(&new_scan);
            return 1;
        }
    }

    bool color = use_color && fp == stdout;
    int rc = 0;

    if (strcasecmp(resolved_format, "text") == 0 || strcasecmp(resolved_format, "diff") == 0)
        print_text(fp, &old_scan, &new_scan, color, old_path, new_path);
    else if (strcasecmp(resolved_format, "json") == 0)
        print_json(fp, &old_scan, &new_scan);
    else if (strcasecmp(resolved_format, "html") == 0)
        print_html(fp, &old_scan, &new_scan, old_path, new_path);
    else if (strcasecmp(resolved_format, "md") == 0)
        print_md(fp, &old_scan, &new_scan, old_path, new_path);
    else if (strcasecmp(resolved_format, "xml") == 0)
        print_xml(fp, &old_scan, &new_scan, old_path, new_path);
    else if (strcasecmp(resolved_format, "sarif") == 0)
        print_sarif(fp);
    else
    {
        fprintf(stderr, "[recon-diff] unsupported format: %s\n", resolved_format);
        rc = 2;
    }

    if (fp != stdout)
        fclose(fp);

    free_scan(&old_scan);
    free_scan(&new_scan);
    return rc;
}
