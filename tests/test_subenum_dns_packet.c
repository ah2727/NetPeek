#include "test.h"
#include "subenum/dns_packet.h"

NP_TEST(subenum_dns_encode_decode)
{
    uint8_t buf[512];
    int n;
    size_t off = 0;
    char out[128];

    n = np_dns_encode_name("api.example.com", buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_EQ_INT(0, np_dns_decode_name(buf, (size_t)n, &off, out, sizeof(out)));
    ASSERT_EQ_STR("api.example.com", out);
}

NP_TEST(subenum_dns_build_query)
{
    uint8_t pkt[512];
    int len = np_dns_build_query(pkt, sizeof(pkt), 0x1234, "example.com", NP_DNS_REC_A);
    ASSERT_TRUE(len > 12);
    ASSERT_EQ_INT(0x12, pkt[0]);
    ASSERT_EQ_INT(0x34, pkt[1]);
}

void register_subenum_dns_packet_tests(void)
{
    NP_REGISTER(subenum_dns_encode_decode);
    NP_REGISTER(subenum_dns_build_query);
}
