#include "test.h"
#include "core/checksum.h"
#include <stdint.h>

NP_TEST(checksum_empty) {
    ASSERT_EQ_INT(0xFFFF, np_checksum16("", 0));
}
NP_TEST(checksum_single_byte) {
    uint8_t d[] = {0x01};
    ASSERT_EQ_INT(0xFEFF, np_checksum16(d, sizeof(d)));
}
NP_TEST(checksum_two_bytes) {
    uint8_t d[] = {0x01, 0x02};
    ASSERT_EQ_INT(0xFEFD, np_checksum16(d, sizeof(d)));
}
NP_TEST(checksum_odd_len) {
    uint8_t d[] = {0x45,0x00,0x00};
    ASSERT_TRUE(np_checksum16(d, sizeof(d)) != 0);
}
NP_TEST(checksum_ipv4_header_like) {
    uint8_t hdr[] = {0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,0x40,0x01,0x00,0x00,0x7f,0x00,0x00,0x01,0x7f,0x00,0x00,0x01};
    uint16_t c = np_checksum16(hdr, sizeof(hdr));
    ASSERT_TRUE(c != 0);
}
NP_TEST(checksum_repeatable) {
    uint8_t d[] = {1,2,3,4,5,6,7,8,9};
    ASSERT_EQ_INT(np_checksum16(d,sizeof(d)), np_checksum16(d,sizeof(d)));
}
NP_TEST(checksum_null_ptr_len0) {
    ASSERT_EQ_INT(0xFFFF, np_checksum16(NULL, 0));
}

void register_checksum_tests(void)
{
    NP_REGISTER(checksum_empty);
    NP_REGISTER(checksum_single_byte);
    NP_REGISTER(checksum_two_bytes);
    NP_REGISTER(checksum_odd_len);
    NP_REGISTER(checksum_ipv4_header_like);
    NP_REGISTER(checksum_repeatable);
    NP_REGISTER(checksum_null_ptr_len0);
}
