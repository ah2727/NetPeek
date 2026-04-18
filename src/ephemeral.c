#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

uint16_t np_random_ephemeral_port(void)
{
    static int seeded = 0;
    if (!seeded)
    {
        seeded = 1;
        srand((unsigned int)(time(NULL) ^ getpid()));
    }

    /* IANA ephemeral range */
    return (uint16_t)(49152 + (rand() % (65535 - 49152)));
}
