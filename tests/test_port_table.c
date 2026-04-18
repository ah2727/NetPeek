#include "test.h"

#include <stdint.h>

#include "recon/port_table.h"

static void read_file(FILE *fp, char *buf, size_t cap)
{
    if (!fp || !buf || cap == 0)
        return;

    rewind(fp);
    size_t n = fread(buf, 1, cap - 1, fp);
    buf[n] = '\0';
}

NP_TEST(port_table_renders_ascii_headers_and_rows)
{
    FILE *fp = tmpfile();
    ASSERT_TRUE(fp != NULL);

    np_port_table_row_t rows[2] = {0};
    snprintf(rows[0].port, sizeof(rows[0].port), "%u", 161u);
    snprintf(rows[0].proto, sizeof(rows[0].proto), "udp");
    snprintf(rows[0].service, sizeof(rows[0].service), "snmp");
    snprintf(rows[0].state, sizeof(rows[0].state), "open");

    snprintf(rows[1].port, sizeof(rows[1].port), "%u", 1812u);
    snprintf(rows[1].proto, sizeof(rows[1].proto), "udp");
    snprintf(rows[1].service, sizeof(rows[1].service), "radius");
    snprintf(rows[1].state, sizeof(rows[1].state), "open|filtered");

    np_port_table_opts_t opts = {.indent = "", .force_ascii = true};
    np_port_table_render(fp, rows, 2, &opts);

    char out[4096];
    read_file(fp, out, sizeof(out));

    ASSERT_TRUE(strstr(out, "| Port") != NULL);
    ASSERT_TRUE(strstr(out, "| Proto") != NULL);
    ASSERT_TRUE(strstr(out, "snmp") != NULL);
    ASSERT_TRUE(strstr(out, "open|filtered") != NULL);

    fclose(fp);
}

NP_TEST(port_table_renders_empty_placeholder)
{
    FILE *fp = tmpfile();
    ASSERT_TRUE(fp != NULL);

    np_port_table_opts_t opts = {.indent = "", .force_ascii = true};
    np_port_table_render(fp, NULL, 0, &opts);

    char out[2048];
    read_file(fp, out, sizeof(out));

    ASSERT_TRUE(strstr(out, "none") != NULL);
    fclose(fp);
}

void register_port_table_tests(void)
{
    NP_REGISTER(port_table_renders_ascii_headers_and_rows);
    NP_REGISTER(port_table_renders_empty_placeholder);
}
