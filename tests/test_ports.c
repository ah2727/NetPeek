#include "test.h"
#include "ports.h"

NP_TEST(ports_single) {
    np_port_spec_t s={0}; ASSERT_TRUE(np_parse_ports("80", &s)); ASSERT_EQ_INT(1, s.count); ASSERT_EQ_INT(80, s.ranges[0].start);
}
NP_TEST(ports_range) {
    np_port_spec_t s={0}; ASSERT_TRUE(np_parse_ports("20-25", &s)); ASSERT_EQ_INT(1, s.count); ASSERT_EQ_INT(20, s.ranges[0].start); ASSERT_EQ_INT(25, s.ranges[0].end);
}
NP_TEST(ports_multi) {
    np_port_spec_t s={0}; ASSERT_TRUE(np_parse_ports("22,80,443", &s)); ASSERT_EQ_INT(3, s.count);
}
NP_TEST(ports_mixed) {
    np_port_spec_t s={0}; ASSERT_TRUE(np_parse_ports("53,100-102", &s)); ASSERT_EQ_INT(2, s.count);
}
NP_TEST(ports_invalid_alpha) {
    np_port_spec_t s={0}; ASSERT_TRUE(!np_parse_ports("abc", &s));
}
NP_TEST(ports_invalid_zero) {
    np_port_spec_t s={0}; ASSERT_TRUE(!np_parse_ports("0", &s));
}
NP_TEST(ports_duplicate_entries) {
    np_port_spec_t s={0}; ASSERT_TRUE(np_parse_ports("80,80", &s)); ASSERT_TRUE(s.count >= 1);
}

void register_ports_tests(void)
{
    NP_REGISTER(ports_single);
    NP_REGISTER(ports_range);
    NP_REGISTER(ports_multi);
    NP_REGISTER(ports_mixed);
    NP_REGISTER(ports_invalid_alpha);
    NP_REGISTER(ports_invalid_zero);
    NP_REGISTER(ports_duplicate_entries);
}
