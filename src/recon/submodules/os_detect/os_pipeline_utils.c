#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "os_pipeline_priv.h"
#include "os_fingerprint.h" // For np_os_fingerprint_t definition
#include "os_fingerprint_types.h"
// Forward-declare the context struct and other types
// These will be properly included via pipeline_priv.h later
typedef struct np_pipeline_ctx_s np_pipeline_ctx_t;


/* ================================================================ */
/*  Utility: detect localhost                                       */
/* ================================================================ */

bool is_localhost_address(const char *ip)
{
    if (!ip)
        return false;

    if (strcmp(ip, "127.0.0.1") == 0) return true;
    if (strcmp(ip, "::1") == 0) return true;
    if (strcmp(ip, "localhost") == 0) return true;
    if (strncmp(ip, "127.", 4) == 0) return true;

    return false;
}

/* ================================================================ */
/*  Utility: derive OS family from OS name string                   */
/* ================================================================ */
/**
 * @brief Derives the OS family based on a given OS name.
 *
 * This function maps various OS names (including common aliases and patterns)
 * to their corresponding operating system families. It is crucial for
 * categorizing discovered operating systems for reporting and analysis.
 *
 * @param os_name The detected OS name string (e.g., "macOS", "iOS", "FreeBSD").
 * @param family A buffer to store the derived family name.
 * @param family_sz The size of the 'family' buffer.
 */
void derive_os_family(const char *os_name, char *family,
                      size_t family_sz)
{
    if (!os_name || !family || family_sz == 0) {
        if (family && family_sz > 0) {
            strncpy(family, "Unknown", family_sz - 1);
            family[family_sz - 1] = '\0'; // Ensure null termination
        }
        return;
    }

    memset(family, 0, family_sz);

    // This map-based approach is cleaner and more extensible than many if-elses.
    struct
    {
        const char *pattern;
        const char *family;
    } map[] = {
        // Apple Families - Prioritize specific OSes, then generic family
        {"macOS", "macOS"},
        {"macos", "macOS"},
        {"Mac OS", "macOS"},
        {"mac os", "macOS"},
        {"OS X", "macOS"},

        {"iOS", "iOS"}, // Explicitly map iOS
        {"ios", "iOS"},

        {"Darwin", "macOS"},   // Darwin is the kernel for macOS and iOS, often reported as macOS
        {"darwin", "macOS"},

        // Generic Apple, less specific patterns should come later
        {"Apple", "macOS"}, // This might still cause issues if iOS doesn't match explicitly first, but with iOS explicit, it's safer
        {"apple", "macOS"},

        // Windows Families
        {"Windows", "Windows"},
        {"windows", "Windows"},
        {"Win", "Windows"},

        // Linux Families
        {"Linux", "Linux"},
        {"linux", "Linux"},
        {"Ubuntu", "Linux"},
        {"Debian", "Linux"},
        {"CentOS", "Linux"},
        {"Red Hat", "Linux"},
        {"Fedora", "Linux"},
        {"Arch", "Linux"},
        {"Alpine", "Linux"},

        // BSD Families
        {"FreeBSD", "BSD"},
        {"freebsd", "BSD"},
        {"OpenBSD", "BSD"},
        {"NetBSD", "BSD"},

        // Other OS Families
        {"Solaris", "Solaris"},
        {"solaris", "Solaris"},
        {"SunOS", "Solaris"},
        {"AIX", "AIX"},
        {"HP-UX", "HP-UX"},
        {"Android", "Android"},

        // Network Device OS Families
        {"Cisco", "Cisco"},
        {"IOS", "Cisco"}, // Note: This is Cisco IOS, not Apple iOS
        {"Juniper", "Juniper"},

        // Terminator for the loop
        {NULL, NULL}
    };

    // Iterate through the map to find the first matching pattern
    for (int i = 0; map[i].pattern != NULL; i++)
    {
        if (strstr(os_name, map[i].pattern) != NULL)
        {
            // Copy the family name, ensuring null termination
            strncpy(family, map[i].family, family_sz - 1);
            family[family_sz - 1] = '\0'; // Ensure null termination
            return; // Found a match, so we can exit
        }
    }

    // If no pattern matched, assign a default "Unknown" family
    strncpy(family, "Unknown", family_sz - 1);
    family[family_sz - 1] = '\0'; // Ensure null termination
}


/* ================================================================ */
/*  Utility: check if fingerprint is all zeros                      */
/* ================================================================ */

bool fingerprint_is_all_zero(const np_os_fingerprint_t *fp)
{
    if (!fp)
        return true;

    const uint8_t *bytes = (const uint8_t *)fp;
    size_t sz = sizeof(np_os_fingerprint_t);
    for (size_t i = 0; i < sz; i++)
    {
        if (bytes[i] != 0)
            return false;
    }
    return true;
}

/* ================================================================ */
/*  Utility: get TTL from a normal TCP connection                   */
/* ================================================================ */

int get_ttl_from_connect(const char *ip, uint16_t port, uint32_t timeout_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
    {
        close(sock);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return -1;
    }

    int ttl = 0;
    socklen_t ttl_len = sizeof(ttl);
    if (getsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, &ttl_len) < 0)
    {
        close(sock);
        return -1;
    }

    close(sock);
    return ttl;
}

/* ================================================================ */
/*  Utility: guess OS from TTL value                                */
/* ================================================================ */

const char *guess_os_from_ttl(int ttl)
{
    if (ttl <= 0) return NULL;
    // Standard initial TTLs are powers of 2 (32, 64, 128, 255).
    // The received TTL is this initial value minus hop count.
    if (ttl > 128) return "Solaris/Cisco"; // Typically start at 255
    if (ttl > 64) return "Windows";         // Typically start at 128
    if (ttl > 32) return "Linux/macOS";     // Typically start at 64, but can't distinguish
    // Below 32 is too ambiguous.
    return NULL;
}
