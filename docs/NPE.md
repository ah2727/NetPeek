================================================================================
                    NPE — NetPeek Extension Engine
                         FULL MASTER PLAN
================================================================================


================================================================================
SECTION 1: NAMING AND IDENTITY
================================================================================

Engine Name:          NPE (NetPeek Extension Engine)
Script Extension:     .npe
Script Language:      Lua (system-installed, linked via include)
Script Directory:     scripts/
Script Database:      scripts/script.db
CLI Flag Prefix:      --script, --script-args, --script-category


================================================================================
SECTION 2: LUA DEPENDENCY — SYSTEM LIBRARY LINKING (NO BUNDLED SOURCE)
================================================================================

CRITICAL RULE:
    Lua is NOT bundled inside the NetPeek source tree.
    Lua is linked as an external system library.
    The user must have Lua development headers installed on their system.

Installation Requirements:

    macOS:
        brew install lua

    Debian / Ubuntu:
        sudo apt install liblua5.4-dev

    Fedora / RHEL:
        sudo dnf install lua-devel

    Arch:
        sudo pacman -S lua

    FreeBSD:
        pkg install lua54

Header Include:
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>

Makefile Linking:
    Use pkg-config to find system Lua:

        LUA_CFLAGS  = $(shell pkg-config --cflags lua5.4 2>/dev/null || pkg-config --cflags lua)
        LUA_LDFLAGS = $(shell pkg-config --libs   lua5.4 2>/dev/null || pkg-config --libs   lua)

    Append to compiler flags:
        CFLAGS  += $(LUA_CFLAGS)
        LDFLAGS += $(LUA_LDFLAGS)

    If pkg-config is not available, fall back to manual paths:
        CFLAGS  += -I/usr/local/include/lua5.4
        LDFLAGS += -L/usr/local/lib -llua5.4

    On macOS with Homebrew:
        CFLAGS  += -I$(shell brew --prefix lua)/include/lua
        LDFLAGS += -L$(shell brew --prefix lua)/lib -llua

Verification:
    The Makefile should check for Lua availability at the top:

        Check if lua.h is found.
        If not found, print:
            "ERROR: Lua development headers not found."
            "Install with: brew install lua / apt install liblua5.4-dev"
        And abort the build.

Minimum Lua Version:
    Lua 5.3 or higher.
    Lua 5.4 preferred.

Why System Lua:
    - Keeps repository clean (no third-party source in tree)
    - Matches how serious C projects handle dependencies
    - System Lua is maintained, patched, and optimized by package managers
    - Reduces repo size significantly
    - Avoids license complications of bundling


================================================================================
SECTION 3: FULL DIRECTORY STRUCTURE
================================================================================

NetPeek/
│
├── include/
│   ├── (existing netpeek headers)
│   │
│   ├── npe/
│   │   ├── npe.h                     Main NPE public API
│   │   ├── npe_types.h               Type definitions, enums, constants
│   │   ├── npe_engine.h              Engine lifecycle (init, run, shutdown)
│   │   ├── npe_script.h              Script structure definition
│   │   ├── npe_loader.h              Script file loading and parsing
│   │   ├── npe_scheduler.h           Execution scheduling and work queue
│   │   ├── npe_runtime.h             Lua VM wrapper and runtime management
│   │   ├── npe_context.h             Per-script execution context
│   │   ├── npe_registry.h            Script database and lookup registry
│   │   ├── npe_result.h              Script result collection
│   │   ├── npe_error.h               Error codes and error handling
│   │   └── npe_sandbox.h             Sandbox and security restrictions
│   │
│   ├── npe_lib/
│   │   ├── npe_lib.h                 Master include for all libraries
│   │   ├── npe_lib_net.h             Network socket operations
│   │   ├── npe_lib_http.h            HTTP client
│   │   ├── npe_lib_dns.h             DNS resolver
│   │   ├── npe_lib_ssl.h             SSL/TLS operations
│   │   ├── npe_lib_crypto.h          Cryptographic utilities
│   │   ├── npe_lib_string.h          String manipulation utilities
│   │   ├── npe_lib_regex.h           Regular expression matching
│   │   ├── npe_lib_json.h            JSON parse and generate
│   │   ├── npe_lib_xml.h             XML parsing
│   │   ├── npe_lib_base64.h          Base64 encode/decode
│   │   ├── npe_lib_hash.h            Hashing (MD5, SHA1, SHA256)
│   │   ├── npe_lib_brute.h           Brute-force framework
│   │   ├── npe_lib_packet.h          Raw packet crafting
│   │   ├── npe_lib_time.h            Timing and delay utilities
│   │   └── npe_lib_fs.h              Safe file read operations
│   │
│   └── npe_proto/
│       ├── npe_proto.h               Master include for protocols
│       ├── npe_proto_ssh.h            SSH protocol interactions
│       ├── npe_proto_ftp.h            FTP protocol interactions
│       ├── npe_proto_smtp.h           SMTP protocol interactions
│       ├── npe_proto_mysql.h          MySQL protocol interactions
│       ├── npe_proto_redis.h          Redis protocol interactions
│       ├── npe_proto_mongodb.h        MongoDB protocol interactions
│       ├── npe_proto_smb.h            SMB protocol interactions
│       ├── npe_proto_snmp.h           SNMP protocol interactions
│       ├── npe_proto_pop3.h           POP3 protocol interactions
│       ├── npe_proto_imap.h           IMAP protocol interactions
│       ├── npe_proto_ldap.h           LDAP protocol interactions
│       └── npe_proto_telnet.h         Telnet protocol interactions
│
├── src/
│   ├── (existing netpeek source files)
│   │
│   ├── npe/
│   │   ├── npe_engine.c              Engine init, run loop, shutdown
│   │   ├── npe_loader.c              Find, read, validate script files
│   │   ├── npe_scheduler.c           Work queue, thread pool, async dispatch
│   │   ├── npe_runtime.c             Lua state creation, library registration
│   │   ├── npe_context.c             Build per-script host/port context
│   │   ├── npe_registry.c            Script database, category index
│   │   ├── npe_result.c              Collect and format script output
│   │   ├── npe_error.c               Error message lookup and reporting
│   │   └── npe_sandbox.c             Restrict dangerous Lua functions
│   │
│   ├── npe_lib/
│   │   ├── npe_lib_net.c             TCP/UDP/RAW socket operations
│   │   ├── npe_lib_http.c            HTTP GET/POST/HEAD client
│   │   ├── npe_lib_dns.c             DNS A/AAAA/MX/NS/TXT resolution
│   │   ├── npe_lib_ssl.c             SSL/TLS connect, cert extraction
│   │   ├── npe_lib_crypto.c          AES, RSA, random bytes
│   │   ├── npe_lib_string.c          Split, trim, match, replace
│   │   ├── npe_lib_regex.c           POSIX or PCRE regex
│   │   ├── npe_lib_json.c            Parse JSON to Lua table, generate JSON
│   │   ├── npe_lib_xml.c             Parse XML to Lua table
│   │   ├── npe_lib_base64.c          Encode/decode base64
│   │   ├── npe_lib_hash.c            MD5, SHA1, SHA256, SHA512
│   │   ├── npe_lib_brute.c           Username/password iteration framework
│   │   ├── npe_lib_packet.c          Craft TCP/UDP/ICMP packets
│   │   ├── npe_lib_time.c            Sleep, timestamp, elapsed
│   │   └── npe_lib_fs.c              Read-only file access (sandboxed)
│   │
│   └── npe_proto/
│       ├── npe_proto_ssh.c            SSH banner, auth, key exchange
│       ├── npe_proto_ftp.c            FTP banner, login, directory
│       ├── npe_proto_smtp.c           SMTP banner, EHLO, VRFY
│       ├── npe_proto_mysql.c          MySQL handshake, version, auth
│       ├── npe_proto_redis.c          Redis INFO, AUTH, PING
│       ├── npe_proto_mongodb.c        MongoDB ismaster, buildinfo
│       ├── npe_proto_smb.c            SMB negotiate, session, enum
│       ├── npe_proto_snmp.c           SNMP GET, walk, community
│       ├── npe_proto_pop3.c           POP3 banner, capabilities
│       ├── npe_proto_imap.c           IMAP banner, capabilities
│       ├── npe_proto_ldap.c           LDAP bind, search
│       └── npe_proto_telnet.c         Telnet banner, negotiation
│
├── scripts/
│   │
│   ├── script.db                      Auto-generated script database index
│   │
│   ├── default/
│   │   ├── banner-grab.npe            Grab service banner from any port
│   │   ├── http-title.npe             Extract HTML page title
│   │   ├── ssh-version.npe            Detect SSH server version
│   │   ├── ssl-cert.npe               Extract SSL certificate details
│   │   └── dns-info.npe               Gather DNS information
│   │
│   ├── discovery/
│   │   ├── http-headers.npe           Enumerate HTTP response headers
│   │   ├── http-methods.npe           Detect allowed HTTP methods
│   │   ├── http-robots.npe            Fetch and parse robots.txt
│   │   ├── http-sitemap.npe           Fetch and parse sitemap.xml
│   │   ├── ftp-anon.npe               Check anonymous FTP login
│   │   ├── mysql-info.npe             MySQL server information
│   │   ├── redis-info.npe             Redis server information
│   │   ├── smb-enum-shares.npe        Enumerate SMB shares
│   │   ├── snmp-info.npe              SNMP system information
│   │   └── smtp-commands.npe          SMTP supported commands
│   │
│   ├── vuln/
│   │   ├── ssl-heartbleed.npe         CVE-2014-0160 Heartbleed
│   │   ├── ssl-poodle.npe             CVE-2014-3566 POODLE
│   │   ├── http-shellshock.npe        CVE-2014-6271 Shellshock
│   │   ├── http-log4shell.npe         CVE-2021-44228 Log4Shell
│   │   ├── smb-ms17-010.npe           MS17-010 EternalBlue
│   │   ├── http-vuln-cve.npe          Generic CVE checker
│   │   └── ssl-ccs-injection.npe      CVE-2014-0224
│   │
│   ├── auth/
│   │   ├── ssh-brute.npe              SSH brute force
│   │   ├── ftp-brute.npe              FTP brute force
│   │   ├── http-brute.npe             HTTP basic auth brute force
│   │   ├── mysql-brute.npe            MySQL brute force
│   │   ├── redis-brute.npe            Redis brute force
│   │   └── smtp-brute.npe             SMTP brute force
│   │
│   ├── safe/
│   │   ├── http-favicon.npe           Identify by favicon hash
│   │   ├── http-server-header.npe     Server header extraction
│   │   ├── ssl-enum-ciphers.npe       Enumerate SSL/TLS ciphers
│   │   ├── whois-ip.npe               WHOIS lookup
│   │   └── traceroute-geo.npe         Geolocation traceroute
│   │
│   └── intrusive/
│       ├── http-sql-injection.npe     SQL injection detection
│       ├── http-xss-detect.npe        XSS detection
│       ├── http-csrf-detect.npe       CSRF detection
│       └── http-directory-enum.npe    Directory enumeration
│
├── tests/
│   └── npe/
│       ├── test_engine.c              Engine init/shutdown tests
│       ├── test_loader.c              Script loading tests
│       ├── test_runtime.c             Lua VM tests
│       ├── test_scheduler.c           Scheduling tests
│       ├── test_sandbox.c             Sandbox restriction tests
│       ├── test_lib_net.c             Network library tests
│       ├── test_lib_http.c            HTTP library tests
│       ├── test_lib_dns.c             DNS library tests
│       └── test_scripts.c             Integration tests with real scripts
│
├── docs/
│   └── npe/
│       ├── OVERVIEW.md                Engine architecture overview
│       ├── INSTALL.md                 Lua dependency installation guide
│       ├── SCRIPTING.md               How to write NPE scripts
│       ├── API.md                     Complete library API reference
│       ├── CATEGORIES.md              Script category definitions
│       ├── SANDBOX.md                 Security model documentation
│       └── EXAMPLES.md               Example scripts walkthrough
│
├── Makefile                           Updated with NPE build targets
├── README.md                          Updated with NPE section
└── .gitignore                         Updated to ignore build artifacts

  
================================================================================
SECTION 4: LUA EMBEDDING ARCHITECTURE
================================================================================

OVERVIEW:
    Every script execution creates a fresh Lua state (lua_State).
    The NPE runtime opens this state, loads sandboxed standard libraries,
    registers all NPE C libraries as Lua modules, sets up the context
    (host, port, args), then executes the script file.

LUA STATE LIFECYCLE:

    1. Create State
         lua_State *L = luaL_newstate()

    2. Open Safe Standard Libraries
         Open only safe libs:
             - base (with dangerous functions removed)
             - string
             - table
             - math
             - os (only os.time, os.clock — remove os.execute, os.exit, etc.)
         Do NOT open:
             - io (filesystem access)
             - debug (can break sandbox)
             - package (can load arbitrary .so/.dll)

    3. Remove Dangerous Globals
         Remove from the Lua global table:
             - dofile
             - loadfile
             - load (or restrict it)
             - rawget / rawset (optional, depends on security level)
             - collectgarbage (optional)
             - os.execute
             - os.exit
             - os.remove
             - os.rename
             - os.tmpname
             - os.getenv

    4. Register NPE Libraries
         Each C library is registered as a Lua module table.
         Example registrations:
             "net"       -> npe_lib_net functions
             "http"      -> npe_lib_http functions
             "dns"       -> npe_lib_dns functions
             "ssl"       -> npe_lib_ssl functions
             "crypto"    -> npe_lib_crypto functions
             "json"      -> npe_lib_json functions
             "xml"       -> npe_lib_xml functions
             "base64"    -> npe_lib_base64 functions
             "hash"      -> npe_lib_hash functions
             "regex"     -> npe_lib_regex functions
             "brute"     -> npe_lib_brute functions
             "packet"    -> npe_lib_packet functions
             "time"      -> npe_lib_time functions
             "fs"        -> npe_lib_fs functions (read-only)

         Each registration uses:
             luaL_newlib(L, function_array)
             lua_setglobal(L, "library_name")

    5. Set Context Globals
         Push host information as a Lua table:
             host.ip           = "192.168.1.10"
             host.name         = "server.local"
             host.os           = "Linux"
             host.mac          = "AA:BB:CC:DD:EE:FF"

         Push port information as a Lua table:
             port.number       = 80
             port.protocol     = "tcp"
             port.state        = "open"
             port.service      = "http"
             port.version      = "Apache 2.4.41"

         Push script arguments as a Lua table:
             args.user         = "admin"
             args.pass         = "password"
             args.threads      = "10"

    6. Load Script File
         luaL_loadfile(L, "scripts/http-title.npe")
         lua_pcall(L, 0, 0, 0)

         This executes the top-level script code, which defines:
             - description (string)
             - author (string)
             - categories (table)
             - portrule or hostrule (function)
             - action (function)

    7. Check Rule
         For portrule:
             lua_getglobal(L, "portrule")
             Push host table
             Push port table
             lua_pcall(L, 2, 1, 0)
             Check boolean return

         For hostrule:
             lua_getglobal(L, "hostrule")
             Push host table
             lua_pcall(L, 1, 1, 0)
             Check boolean return

         If rule returns false/nil:
             Skip this script for this host/port.

    8. Execute Action
         lua_getglobal(L, "action")
         Push host table
         Push port table
         lua_pcall(L, 2, 1, 0)

         Read return value:
             If string: script output text
             If table: structured output (convert to npe_result)
             If nil: script produced no output

    9. Collect Result
         Extract the return value from Lua stack.
         Package into npe_result_t structure.
         Add to result aggregator.

    10. Destroy State
         lua_close(L)
         Free associated resources.


MEMORY MANAGEMENT:
    Each Lua state has its own memory.
    Use a custom allocator (lua_Alloc) that tracks memory per script.
    Set a memory limit per script (default 16 MB).
    If a script exceeds the limit, the allocator returns NULL
    and Lua raises an out-of-memory error.

    Custom allocator signature:
        void *npe_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)

    The ud (userdata) pointer points to a tracking structure:
        - bytes_allocated (current)
        - bytes_limit (maximum)
        - allocation_count

TIMEOUT ENFORCEMENT:
    Use lua_sethook to install a count hook.
    Every N instructions (e.g., 1,000,000), the hook fires.
    The hook checks elapsed wall-clock time.
    If timeout exceeded, call luaL_error(L, "script timeout").

    Hook signature:
        void npe_timeout_hook(lua_State *L, lua_Debug *ar)

    This prevents infinite loops and runaway scripts.

ERROR HANDLING:
    All lua_pcall calls check return value.
    On error:
        Extract error message: lua_tostring(L, -1)
        Log the error with script name and line number.
        Mark script result as failed.
        Continue to next script (never crash the engine).


================================================================================
SECTION 5: C LIBRARY REGISTRATION — DETAILED FUNCTION LISTS
================================================================================

Each library is an array of luaL_Reg entries.
Each entry maps a Lua function name to a C function pointer.

--- NET LIBRARY ---
    net.connect(ip, port)              Open TCP connection, return socket object
    net.connect_udp(ip, port)          Open UDP socket
    net.connect_ssl(ip, port)          Open SSL/TLS connection
    net.send(socket, data)             Send data on socket
    net.recv(socket)                   Receive data from socket
    net.recv_bytes(socket, n)          Receive exactly n bytes
    net.recv_until(socket, delimiter)  Receive until delimiter found
    net.recv_timeout(socket, ms)       Receive with timeout
    net.close(socket)                  Close socket
    net.set_timeout(socket, ms)        Set socket timeout
    net.getpeername(socket)            Get remote address
    net.getsockname(socket)            Get local address

--- HTTP LIBRARY ---
    http.get(url)                      HTTP GET request
    http.post(url, body)               HTTP POST request
    http.head(url)                     HTTP HEAD request
    http.put(url, body)                HTTP PUT request
    http.delete(url)                   HTTP DELETE request
    http.request(options_table)        Generic request with full options
    http.pipeline(requests_table)      Pipelined HTTP requests

    Return table:
        status                         HTTP status code (number)
        headers                        Response headers (table)
        body                           Response body (string)
        cookies                        Cookies (table)

--- DNS LIBRARY ---
    dns.resolve(hostname)              Resolve A record
    dns.resolve6(hostname)             Resolve AAAA record
    dns.reverse(ip)                    Reverse DNS lookup
    dns.mx(domain)                     MX records
    dns.ns(domain)                     NS records
    dns.txt(domain)                    TXT records
    dns.srv(domain)                    SRV records
    dns.soa(domain)                    SOA record
    dns.axfr(domain, server)           Zone transfer attempt
    dns.query(name, type, class)       Raw DNS query

--- SSL LIBRARY ---
    ssl.connect(ip, port)              SSL/TLS connection
    ssl.get_cert(ip, port)             Get server certificate
    ssl.get_cert_chain(ip, port)       Get full certificate chain
    ssl.get_cipher(connection)         Get negotiated cipher
    ssl.get_protocol(connection)       Get negotiated protocol version
    ssl.enum_ciphers(ip, port)         Enumerate supported ciphers
    ssl.check_protocol(ip, port, ver)  Check if protocol version supported

    Certificate table:
        subject                        Subject fields (table)
        issuer                         Issuer fields (table)
        serial                         Serial number (string)
        not_before                     Validity start (string)
        not_after                      Validity end (string)
        fingerprint_sha256             SHA256 fingerprint (string)
        public_key_type                Key type (RSA/EC/etc)
        public_key_bits                Key size (number)
        san                            Subject Alternative Names (table)

--- CRYPTO LIBRARY ---
    crypto.md5(data)                   MD5 hash
    crypto.sha1(data)                  SHA1 hash
    crypto.sha256(data)                SHA256 hash
    crypto.sha512(data)                SHA512 hash
    crypto.hmac_sha256(key, data)      HMAC-SHA256
    crypto.hmac_sha1(key, data)        HMAC-SHA1
    crypto.random_bytes(n)             Cryptographic random bytes
    crypto.aes_encrypt(key, data)      AES encryption
    crypto.aes_decrypt(key, data)      AES decryption

--- STRING LIBRARY (extensions beyond Lua built-in) ---
    str.split(s, delimiter)            Split string
    str.trim(s)                        Trim whitespace
    str.ltrim(s)                       Left trim
    str.rtrim(s)                       Right trim
    str.starts_with(s, prefix)         Check prefix
    str.ends_with(s, suffix)           Check suffix
    str.contains(s, substring)         Check contains
    str.hex_encode(data)               Hex encode
    str.hex_decode(hex)                Hex decode
    str.url_encode(s)                  URL encode
    str.url_decode(s)                  URL decode

--- JSON LIBRARY ---
    json.parse(json_string)            Parse JSON to Lua table
    json.encode(lua_table)             Encode Lua table to JSON string
    json.pretty(lua_table)             Pretty-printed JSON

--- XML LIBRARY ---
    xml.parse(xml_string)              Parse XML to Lua table
    xml.find(doc, xpath)               XPath-like query

--- BASE64 LIBRARY ---
    base64.encode(data)                Base64 encode
    base64.decode(b64_string)          Base64 decode

--- REGEX LIBRARY ---
    regex.match(subject, pattern)      Match and return captures
    regex.find(subject, pattern)       Find first match position
    regex.gmatch(subject, pattern)     Iterator over all matches
    regex.gsub(subject, pattern, rep)  Global substitution

--- HASH LIBRARY (alias for common crypto hashing) ---
    hash.md5(data)                     MD5 digest hex string
    hash.sha1(data)                    SHA1 digest hex string
    hash.sha256(data)                  SHA256 digest hex string
    hash.crc32(data)                   CRC32 checksum

--- BRUTE LIBRARY ---
    brute.start(options_table)         Start brute-force session
        options:
            login_function             Function(username, password) -> bool, msg
            username_list              File path or table of usernames
            password_list              File path or table of passwords
            threads                    Concurrent attempts
            delay                      Delay between attempts (ms)
            max_attempts               Maximum total attempts

--- PACKET LIBRARY ---
    packet.tcp(options)                Craft TCP packet
    packet.udp(options)                Craft UDP packet
    packet.icmp(options)               Craft ICMP packet
    packet.send(raw_data)              Send raw packet
    packet.recv(timeout)               Receive raw packet

--- TIME LIBRARY ---
    time.now()                         Current timestamp (seconds)
    time.now_ms()                      Current timestamp (milliseconds)
    time.sleep(seconds)                Sleep (float seconds)
    time.sleep_ms(ms)                  Sleep (milliseconds)
    time.elapsed(start)                Elapsed since start

--- FS LIBRARY (sandboxed, read-only) ---
    fs.read(path)                      Read file contents (restricted paths only)
    fs.exists(path)                    Check if file exists
    fs.lines(path)                     Iterator over file lines
    fs.size(path)                      Get file size

    Sandbox rules for fs:
        Only allow reading from:
            - scripts/ directory
            - data/ directory (wordlists, fingerprints)
        Block all absolute paths.
        Block path traversal (../).
        Block reading outside allowed directories.
        Block all write operations.


================================================================================
SECTION 6: PROTOCOL LIBRARY FUNCTIONS
================================================================================

--- SSH PROTOCOL ---
    ssh.banner(ip, port)               Get SSH banner string
    ssh.version(ip, port)              Parse SSH version info
    ssh.algorithms(ip, port)           List supported algorithms
    ssh.hostkey(ip, port)              Get host key fingerprint
    ssh.auth_methods(ip, port)         Supported auth methods

--- FTP PROTOCOL ---
    ftp.banner(ip, port)               Get FTP banner
    ftp.login(ip, port, user, pass)    Login attempt
    ftp.anonymous(ip, port)            Check anonymous access
    ftp.list(session, path)            Directory listing
    ftp.syst(session)                  SYST command
    ftp.features(session)              FEAT command

--- SMTP PROTOCOL ---
    smtp.banner(ip, port)              Get SMTP banner
    smtp.ehlo(ip, port, domain)        EHLO and get extensions
    smtp.vrfy(session, address)        VRFY command
    smtp.expn(session, list)           EXPN command
    smtp.starttls(session)             STARTTLS negotiation
    smtp.auth_methods(session)         Supported auth methods

--- MYSQL PROTOCOL ---
    mysql.banner(ip, port)             Get MySQL handshake info
    mysql.version(ip, port)            Parse version
    mysql.login(ip, port, user, pass)  Login attempt
    mysql.query(session, sql)          Execute query
    mysql.databases(session)           List databases

--- REDIS PROTOCOL ---
    redis.info(ip, port)               INFO command
    redis.ping(ip, port)               PING command
    redis.auth(ip, port, password)     AUTH command
    redis.command(session, cmd)        Generic command

--- MONGODB PROTOCOL ---
    mongodb.ismaster(ip, port)         isMaster command
    mongodb.buildinfo(ip, port)        buildInfo command
    mongodb.listdbs(session)           List databases
    mongodb.serverinfo(ip, port)       Server information

--- SMB PROTOCOL ---
    smb.negotiate(ip, port)            Protocol negotiation
    smb.session(ip, port)              Session setup
    smb.enum_shares(session)           List shares
    smb.enum_users(session)            List users
    smb.os_info(session)               OS discovery

--- SNMP PROTOCOL ---
    snmp.get(ip, community, oid)       SNMP GET
    snmp.getnext(ip, community, oid)   SNMP GETNEXT
    snmp.walk(ip, community, oid)      SNMP walk
    snmp.set(ip, community, oid, val)  SNMP SET
    snmp.sysinfo(ip, community)        System info OIDs

--- TELNET PROTOCOL ---
    telnet.banner(ip, port)            Get telnet banner
    telnet.negotiate(ip, port)         Option negotiation
    telnet.interact(session, cmd)      Send command, get response

--- POP3 PROTOCOL ---
    pop3.banner(ip, port)              Get POP3 banner
    pop3.capabilities(ip, port)        CAPA command
    pop3.login(ip, port, user, pass)   Login attempt

--- IMAP PROTOCOL ---
    imap.banner(ip, port)              Get IMAP banner
    imap.capabilities(ip, port)        CAPABILITY command
    imap.login(ip, port, user, pass)   Login attempt

--- LDAP PROTOCOL ---
    ldap.bind(ip, port, dn, pass)      LDAP bind
    ldap.search(session, base, filter) LDAP search
    ldap.rootdse(ip, port)             Root DSE query


================================================================================
SECTION 7: NPE ENGINE CORE — COMPONENT DESIGN
================================================================================

--- NPE_ENGINE ---
    Purpose:    Top-level engine lifecycle management.
    Functions:
        npe_engine_init(config)        Initialize engine with configuration
        npe_engine_load_scripts(dir)   Load all scripts from directory
        npe_engine_run(scan_results)   Execute scripts against scan results
        npe_engine_shutdown()          Clean up all resources
        npe_engine_get_results()       Retrieve all script results

    Configuration:
        script_directory               Path to scripts folder
        categories                     Which categories to run
        specific_scripts               Specific script names to run
        script_args                    Key-value arguments for scripts
        max_concurrent                 Max concurrent script executions
        timeout_ms                     Per-script timeout
        memory_limit                   Per-script memory limit
        verbosity                      Output verbosity level

--- NPE_LOADER ---
    Purpose:    Find, read, and validate script files.
    Functions:
        npe_loader_scan_directory(dir) Scan directory for .npe files
        npe_loader_load_script(path)   Load single script metadata
        npe_loader_validate(script)    Validate script structure
        npe_loader_parse_metadata(L)   Extract metadata from loaded Lua state
        npe_loader_build_database()    Build/update script.db index

    Loading Process:
        1. Scan scripts/ directory recursively for .npe files
        2. For each file:
            a. Create temporary Lua state
            b. Load file
            c. Extract description, author, categories
            d. Determine phase (portrule, hostrule, prerule, postrule)
            e. Store metadata in script struct
            f. Close temporary state
        3. Register all scripts in registry
        4. Write script.db index

--- NPE_SCHEDULER ---
    Purpose:    Manage execution order and concurrency.
    Functions:
        npe_scheduler_init(config)     Initialize scheduler
        npe_scheduler_queue(script, host, port)  Queue script execution
        npe_scheduler_run()            Process queue
        npe_scheduler_wait()           Wait for all scripts to complete
        npe_scheduler_shutdown()       Destroy scheduler

    Design:
        Thread pool with configurable size (default: 8 threads).
        Work queue (thread-safe, mutex + condition variable).
        Each work item contains:
            - Script reference
            - Host information
            - Port information
            - Script arguments
        Worker threads pull items from queue.
        Each worker creates its own Lua state (no sharing).
        Results pushed to result queue (thread-safe).

    Execution Order:
        Phase 1: Run all prerule scripts
        Phase 2: For each host, run hostrule scripts
        Phase 3: For each host/port, run portrule scripts
        Phase 4: Run all postrule scripts

    Dependencies:
        If script A depends on script B:
            B must complete before A is scheduled.
        Dependency resolution uses topological sort.

--- NPE_RUNTIME ---
    Purpose:    Manage Lua VM lifecycle and library registration.
    Functions:
        npe_runtime_create_state()     Create new Lua state with NPE libs
        npe_runtime_destroy_state(L)   Destroy Lua state
        npe_runtime_register_libs(L)   Register all NPE C libraries
        npe_runtime_apply_sandbox(L)   Apply security restrictions
        npe_runtime_set_context(L, h, p)  Set host/port context
        npe_runtime_set_args(L, args)  Set script arguments
        npe_runtime_execute(L, script) Execute script in state
        npe_runtime_collect_result(L)  Collect execution result

--- NPE_CONTEXT ---
    Purpose:    Build per-execution context from scan data.
    Functions:
        npe_context_create(host, port) Create context
        npe_context_push_host(L, ctx)  Push host table to Lua
        npe_context_push_port(L, ctx)  Push port table to Lua
        npe_context_push_args(L, ctx)  Push args table to Lua
        npe_context_destroy(ctx)       Destroy context

    Host Table Fields:
        ip                             Target IP address (string)
        name                           Hostname if resolved (string or nil)
        os                             Detected OS (string or nil)
        mac                            MAC address if available (string or nil)
        status                         Host status: "up" or "down"
        ports                          Table of all scanned ports

    Port Table Fields:
        number                         Port number (integer)
        protocol                       "tcp" or "udp" (string)
        state                          "open", "closed", "filtered" (string)
        service                        Service name if detected (string or nil)
        version                        Version string if detected (string or nil)
        banner                         Raw banner if captured (string or nil)

--- NPE_REGISTRY ---
    Purpose:    Index and look up scripts by various criteria.
    Functions:
        npe_registry_init()            Initialize registry
        npe_registry_add(script)       Add script to registry
        npe_registry_remove(name)      Remove script
        npe_registry_find_by_name(n)   Find by name
        npe_registry_find_by_cat(c)    Find by category
        npe_registry_find_by_port(p)   Find by port
        npe_registry_find_by_phase(p)  Find by phase
        npe_registry_get_all()         Get all registered scripts
        npe_registry_save_db(path)     Save registry to script.db
        npe_registry_load_db(path)     Load registry from script.db
        npe_registry_shutdown()        Destroy registry

    Indexing:
        Hash map by script name       O(1) lookup by name
        Category bitmask index         Fast category filtering
        Port number index              Quick port-based matching
        Phase-grouped lists            Phase-ordered execution

--- NPE_RESULT ---
    Purpose:    Collect, format, and output script results.
    Functions:
        npe_result_create(script, host, port)  Create result container
        npe_result_set_output(result, text)    Set text output
        npe_result_set_table(result, table)    Set structured output
        npe_result_set_error(result, err)      Set error output
        npe_result_format_text(result)         Format as plain text
        npe_result_format_json(result)         Format as JSON
        npe_result_format_csv(result)          Format as CSV
        npe_result_destroy(result)             Free result

    Integration with NetPeek output:
        Results are fed back into the existing output.c formatter.
        Each result is associated with a host/port.
        The output module renders script results under the port entry.

--- NPE_SANDBOX ---
    Purpose:    Security restrictions and resource limits.
    Functions:
        npe_sandbox_apply(L)           Apply all sandbox rules to Lua state
        npe_sandbox_set_memory_limit(L, bytes)  Set memory limit
        npe_sandbox_set_timeout(L, ms)          Set execution timeout
        npe_sandbox_install_hooks(L)   Install instruction count hooks
        npe_sandbox_check_path(path)   Validate file path is allowed

    Rules:
        1. No shell execution (os.execute removed)
        2. No arbitrary file I/O (io library not loaded)
        3. No dynamic library loading (package library not loaded)
        4. No debug library access
        5. Memory limit per script (default 16 MB)
        6. CPU time limit per script (default 30 seconds)
        7. Network connection limit per script (default 100)
        8. File access restricted to scripts/ and data/ directories
        9. No outbound connections to localhost/127.0.0.1 by default
           (configurable)

--- NPE_ERROR ---
    Purpose:    Consistent error handling and reporting.
    Functions:
        npe_error_string(code)         Get human-readable error string
        npe_error_log(code, context)   Log error with context
        npe_error_from_lua(L)          Extract error from Lua state
        npe_error_set_handler(fn)      Set custom error handler callback


================================================================================
SECTION 8: SCRIPT STRUCTURE AND METADATA FORMAT
================================================================================

Every .npe script file follows this structure:

    SECTION: Metadata (global assignments)
        description     (required)     Human-readable description
        author          (required)     Script author
        license         (optional)     License string (default: same as project)
        categories      (required)     Table of category strings

    SECTION: Dependencies (optional)
        dependencies    (optional)     Table of script names this depends on

    SECTION: Rule Function (exactly one required)
        portrule(host, port)           Return true if script should run on port
        hostrule(host)                 Return true if script should run on host
        prerule()                      Always runs before scan
        postrule()                     Always runs after scan

    SECTION: Action Function (required)
        action(host, port)             Main script logic, returns result

    SECTION: Helper Functions (optional)
        Any local functions used by action.


================================================================================
SECTION 9: SCRIPT EXAMPLE STRUCTURES
================================================================================

EXAMPLE 1: Simple banner grab (portrule)

    description = "Grab service banner from open TCP ports"
    author = "NetPeek Team"
    categories = {"default", "discovery", "safe"}

    portrule = function(host, port)
        return port.protocol == "tcp" and port.state == "open"
    end

    action = function(host, port)
        local socket = net.connect(host.ip, port.number)
        if not socket then
            return nil
        end
        net.set_timeout(socket, 5000)
        local banner = net.recv(socket)
        net.close(socket)
        if banner and #banner > 0 then
            return "Banner: " .. banner
        end
        return nil
    end

EXAMPLE 2: HTTP title extraction (portrule)

    description = "Extract HTML page title from HTTP services"
    author = "NetPeek Team"
    categories = {"default", "discovery", "safe"}

    portrule = function(host, port)
        return port.service == "http" or port.number == 80
               or port.number == 8080
    end

    action = function(host, port)
        local resp = http.get("http://" .. host.ip .. ":" 
                              .. port.number .. "/")
        if not resp or resp.status ~= 200 then
            return nil
        end
        local title = string.match(resp.body, "<title>(.-)</title>")
        if title then
            return "Title: " .. str.trim(title)
        end
        return "No title found"
    end

EXAMPLE 3: SSL certificate extraction (portrule)

    description = "Extract SSL/TLS certificate information"
    author = "NetPeek Team"
    categories = {"default", "safe", "discovery"}

    portrule = function(host, port)
        return port.service == "https" or port.number == 443
               or port.number == 8443
    end

    action = function(host, port)
        local cert = ssl.get_cert(host.ip, port.number)
        if not cert then
            return nil
        end
        local output = {}
        table.insert(output, "Subject: " .. cert.subject.CN)
        table.insert(output, "Issuer:  " .. cert.issuer.CN)
        table.insert(output, "Valid:   " .. cert.not_before 
                     .. " to " .. cert.not_after)
        table.insert(output, "SANs:    " .. table.concat(cert.san, ", "))
        return table.concat(output, "\n")
    end

EXAMPLE 4: SSH brute force (auth category)

    description = "Brute-force SSH login"
    author = "NetPeek Team"
    categories = {"auth", "brute", "intrusive"}

    portrule = function(host, port)
        return port.service == "ssh" or port.number == 22
    end

    action = function(host, port)
        local results = brute.start({
            login = function(user, pass)
                local status, err = ssh.login(host.ip, port.number,
                                              user, pass)
                return status, err
            end,
            username_list = "data/usernames.txt",
            password_list = "data/passwords.txt",
            threads = 4,
            delay = 500,
        })
        if results and #results > 0 then
            local output = "Valid credentials found:\n"
            for _, cred in ipairs(results) do
                output = output .. "  " .. cred.user 
                         .. ":" .. cred.pass .. "\n"
            end
            return output
        end
        return nil
    end

EXAMPLE 5: Vulnerability check (vuln category)

    description = "Check for SSL Heartbleed vulnerability (CVE-2014-0160)"
    author = "NetPeek Team"
    categories = {"vuln", "safe"}

    portrule = function(host, port)
        return port.service == "https" or port.number == 443
    end

    action = function(host, port)
        local sock = net.connect_ssl(host.ip, port.number)
        if not sock then
            return nil
        end

        -- Craft heartbleed test payload
        local heartbeat_request = "\x18\x03\x02\x00\x03"
                                  .. "\x01\x40\x00"
        net.send(sock, heartbeat_request)

        local response = net.recv_timeout(sock, 3000)
        net.close(sock)

        if response and #response > 3 then
            return "VULNERABLE: Server responded to heartbeat "
                   .. "with " .. #response .. " bytes"
        end
        return "Not vulnerable"
    end

EXAMPLE 6: Prerule script

    description = "Pre-scan network broadcast discovery"
    author = "NetPeek Team"
    categories = {"discovery", "broadcast"}

    prerule = function()
        return true
    end

    action = function()
        -- Discover hosts via ARP/broadcast before port scanning
        local hosts = packet.arp_scan("192.168.1.0/24")
        local output = "Discovered " .. #hosts .. " hosts:\n"
        for _, h in ipairs(hosts) do
            output = output .. "  " .. h.ip .. " (" .. h.mac .. ")\n"
        end
        return output
    end

EXAMPLE 7: Postrule script

    description = "Post-scan summary and statistics"
    author = "NetPeek Team"
    categories = {"safe"}

    postrule = function()
        return true
    end

    action = function()
        -- Access shared registry for cross-script data
        local total_open = registry.get("total_open_ports") or 0
        local vulns = registry.get("vulnerabilities") or {}
        local output = "Scan Summary:\n"
        output = output .. "  Open ports found: " .. total_open .. "\n"
        output = output .. "  Vulnerabilities:  " .. #vulns .. "\n"
        return output
    end


================================================================================
SECTION 10: SHARED STATE AND SCRIPT COMMUNICATION
================================================================================

Scripts can share data through a thread-safe global registry.

API accessible from Lua:
    registry.set(key, value)           Store value (string, number, table)
    registry.get(key)                  Retrieve value
    registry.append(key, value)        Append to list stored at key
    registry.keys()                    List all keys

C implementation:
    Thread-safe hash map.
    Protected by read-write lock (pthread_rwlock).
    Values serialized/deserialized when crossing thread boundaries.
    Deep copies made to prevent race conditions.

Use cases:
    - Script A detects SSL cert, stores fingerprint
    - Script B reads fingerprint to correlate with known bad certs
    - Postrule scripts aggregate data from all previous scripts
    - Brute-force scripts share discovered credentials


================================================================================
SECTION 11: CLI INTEGRATION
================================================================================

New command-line flags for NetPeek:

    --script <name|category|path>
        Specify scripts to run.
        Accepts:
            Script name:      --script ssh-version
            Category:         --script vuln
            Multiple:         --script "default,vuln"
            File path:        --script ./custom/my-script.npe
            Wildcard:         --script "http-*"
            All:              --script all

    --script-args <key=value,...>
        Pass arguments to scripts.
        Example: --script-args user=admin,pass=secret,threads=10

    --script-args-file <file>
        Load script arguments from file.

    --script-dir <path>
        Override default scripts directory.

    --script-timeout <seconds>
        Override default per-script timeout.

    --script-updatedb
        Regenerate scripts/script.db index.

    --script-help <name>
        Show help for specific script.

    --script-trace
        Enable debug tracing of script execution.

Integration into args.c:
    Add new option parsing for all --script* flags.
    Store in scan configuration structure.
    Pass configuration to NPE engine at startup.


================================================================================
SECTION 12: MAKEFILE UPDATES
================================================================================

New Makefile targets:

    make                    Build NetPeek with NPE
    make npe                Build NPE engine only
    make scripts-db         Regenerate script database
    make test-npe           Run NPE unit tests
    make clean              Clean all build artifacts

New variables:

    LUA_CFLAGS              Lua include path (from pkg-config)
    LUA_LDFLAGS             Lua library path (from pkg-config)
    NPE_SRCS                All NPE source files
    NPE_OBJS                All NPE object files
    NPE_LIB_SRCS            All NPE library source files
    NPE_PROTO_SRCS          All NPE protocol source files

Source groups:

    NPE core:       src/npe/*.c
    NPE libraries:  src/npe_lib/*.c
    NPE protocols:  src/npe_proto/*.c

Build order:
    1. Check Lua availability (fail fast if not found)
    2. Compile NPE core objects
    3. Compile NPE library objects
    4. Compile NPE protocol objects
    5. Compile existing NetPeek objects
    6. Link everything together with Lua


================================================================================
SECTION 13: OUTPUT INTEGRATION
================================================================================

Script results integrate with existing output.c:

PLAIN TEXT FORMAT:
    192.168.1.10
      22/tcp  open  ssh
      | ssh-version:
      |   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
      |_  Key type: ssh-rsa (2048 bits)
      80/tcp  open  http
      | http-title:
      |   Title: Welcome to My Server
      |_
      443/tcp open  https
      | ssl-cert:
      |   Subject: CN=example.com
      |   Issuer:  CN=Let's Encrypt Authority X3
      |   Valid:   2024-01-01 to 2024-12-31
      |_  SANs: example.com, www.example.com

JSON FORMAT:
    {
      "host": "192.168.1.10",
      "ports": [
        {
          "port": 22,
          "state": "open",
          "service": "ssh",
          "scripts": [
            {
              "name": "ssh-version",
              "output": "SSH-2.0-OpenSSH_8.9p1"
            }
          ]
        }
      ]
    }

CSV FORMAT:
    host,port,protocol,state,service,script,output
    192.168.1.10,22,tcp,open,ssh,ssh-version,"SSH-2.0-OpenSSH_8.9p1"
    192.168.1.10,80,tcp,open,http,http-title,"Welcome to My Server"


================================================================================
SECTION 14: SCRIPT DATABASE FORMAT (script.db)
================================================================================

The script.db file is auto-generated.
It allows fast script lookup without loading every .npe file.

Format (one line per script):

    Entry ::= filename | name | categories | phase | ports | dependencies

Example entries:

    default/banner-grab.npe|banner-grab|default,discovery,safe|portrule|*|
    default/http-title.npe|http-title|default,discovery,safe|portrule|80,8080|
    vuln/ssl-heartbleed.npe|ssl-heartbleed|vuln,safe|portrule|443,8443|
    auth/ssh-brute.npe|ssh-brute|auth,brute,intrusive|portrule|22|
    discovery/ftp-anon.npe|ftp-anon|discovery,safe|portrule|21|
    default/ssl-cert.npe|ssl-cert|default,safe,discovery|portrule|443,8443|

Regeneration:
    Run: netpeek --script-updatedb
    Or:  make scripts-db


================================================================================
SECTION 15: ERROR AND LOGGING STRATEGY
================================================================================

Log levels:
    NPE_LOG_ERROR              Script crashes, connection failures
    NPE_LOG_WARN               Timeouts, partial results
    NPE_LOG_INFO               Script start/end, result summary
    NPE_LOG_DEBUG              Detailed execution trace
    NPE_LOG_TRACE              Lua instruction-level tracing

Error scenarios and handling:

    Script syntax error:
        Log error with filename and line number.
        Skip script, continue others.

    Script runtime error:
        Catch via lua_pcall.
        Log error message.
        Mark result as failed.
        Continue other scripts.

    Script timeout:
        Hook fires, calls luaL_error.
        Caught by lua_pcall.
        Log timeout warning.
        Close any open sockets.
        Continue other scripts.

    Script memory exceeded:
        Custom allocator returns NULL.
        Lua raises memory error.
        Caught by lua_pcall.
        Log memory warning.
        Continue other scripts.

    Network error in script:
        Library function returns nil + error message.
        Script handles it (or crashes, caught by pcall).

    NEVER crash the entire engine due to a single script failure.


================================================================================
SECTION 16: PERFORMANCE OPTIMIZATION
================================================================================

SOCKET POOLING:
    Maintain pool of pre-connected sockets when scanning many ports
    on the same host.
    Scripts can reuse connections.

SCRIPT CACHING:
    After first load, keep compiled bytecode in memory.
    Use luaL_loadbuffer with cached bytecode for subsequent executions.
    Avoid re-reading and re-parsing .npe files.

MEMORY POOLS:
    Pre-allocate memory pools for common operations.
    Reduce malloc/free pressure during high-concurrency execution.

ASYNC I/O:
    Use kqueue (macOS) or epoll (Linux) for non-blocking socket operations.
    Allow scripts to yield while waiting for network data.
    Scheduler picks up other scripts during I/O wait.
    Implemented via Lua coroutines:
        Script calls net.recv() -> C code yields coroutine
        Event loop monitors socket
        When data ready -> resume coroutine

BATCHING:
    Group scripts by target host.
    Run all scripts for one host together.
    Reduces connection overhead.

THREAD POOL SIZING:
    Default: min(8, number_of_cpu_cores * 2)
    Configurable via --script-threads


================================================================================
SECTION 17: SECURITY MODEL
================================================================================

THREAT MODEL:
    Scripts may be downloaded from untrusted sources.
    Scripts must not be able to:
        1. Execute system commands
        2. Read/write arbitrary files
        3. Access the host machine beyond network operations
        4. Consume unlimited resources
        5. Interfere with other scripts
        6. Crash the engine

ISOLATION:
    Each script runs in its own Lua state (lua_State).
    No shared Lua state between scripts.
    Shared data only through the registry (C-level, thread-safe).

NETWORK RESTRICTIONS:
    Configurable allowed/denied target lists.
    By default, scripts can only connect to the scan target.
    Optional flag to allow connecting to arbitrary hosts.

RESOURCE LIMITS:
    Memory:     16 MB per script (configurable)
    CPU time:   30 seconds per script (configurable)
    Sockets:    100 concurrent per script (configurable)
    Output:     1 MB per script result (configurable)

AUDIT:
    All script network operations logged at DEBUG level.
    Failed sandbox violations logged at WARN level.


================================================================================
SECTION 18: IMPLEMENTATION PHASES
================================================================================

PHASE 1 — FOUNDATION (Weeks 1-3)
    Goal: Minimal working engine that can load and run one script.

    Tasks:
        - Create src/npe/ directory structure
        - Create all header files with type definitions
        - Implement npe_engine.c (init, shutdown)
        - Implement npe_runtime.c (Lua state creation, library registration)
        - Implement npe_sandbox.c (remove dangerous functions)
        - Implement npe_loader.c (load single .npe file)
        - Implement npe_context.c (push host/port to Lua)
        - Implement npe_result.c (collect script output)
        - Implement npe_lib_net.c (basic TCP connect/send/recv/close)
        - Update Makefile with Lua detection and NPE build
        - Write banner-grab.npe as first test script
        - Integrate with main.c (call NPE after scan)

    Deliverable:
        netpeek --target 192.168.1.1 --ports 22 --script banner-grab
        Runs scan, then runs banner-grab script, shows output.

PHASE 2 — CORE LIBRARIES (Weeks 4-6)
    Goal: Essential libraries for useful scripts.

    Tasks:
        - Implement npe_lib_http.c (GET, POST, HEAD)
        - Implement npe_lib_dns.c (resolve, reverse, MX, NS, TXT)
        - Implement npe_lib_ssl.c (connect, get_cert, enum_ciphers)
        - Implement npe_lib_json.c (parse, encode)
        - Implement npe_lib_string.c (split, trim, hex, url encode)
        - Implement npe_lib_base64.c (encode, decode)
        - Implement npe_lib_hash.c (MD5, SHA1, SHA256)
        - Implement npe_lib_regex.c (match, find, gsub)
        - Implement npe_lib_time.c (sleep, timestamp)
        - Write 10 default scripts using these libraries

    Deliverable:
        netpeek --target scanme.nmap.org --ports 1-1024 --script default
        Runs all default category scripts.

PHASE 3 — SCHEDULER AND CONCURRENCY (Weeks 7-9)
    Goal: High-performance parallel script execution.

    Tasks:
        - Implement npe_scheduler.c (thread pool, work queue)
        - Implement async I/O integration (kqueue/epoll)
        - Implement Lua coroutine-based yielding for network I/O
        - Implement script dependency resolution
        - Implement execution phase ordering (pre/host/port/post)
        - Implement npe_registry.c (script database, category index)
        - Implement script.db generation
        - Implement --script-updatedb
        - Stress test with 100+ concurrent scripts

    Deliverable:
        netpeek --target 10.0.0.0/24 --ports 1-1024 --script default,discovery
        Scans 256 hosts, runs scripts on all open ports concurrently.

PHASE 4 — PROTOCOLS AND ADVANCED LIBRARIES (Weeks 10-13)
    Goal: Protocol-specific libraries and advanced features.

    Tasks:
        - Implement all protocol libraries (SSH, FTP, SMTP, etc.)
        - Implement npe_lib_brute.c (brute-force framework)
        - Implement npe_lib_packet.c (raw packet crafting)
        - Implement npe_lib_crypto.c (AES, HMAC)
        - Implement npe_lib_fs.c (sandboxed file reading)
        - Implement shared registry for cross-script communication
        - Implement --script-args and --script-args-file
        - Implement --script-help
        - Implement --script-trace
        - Write 30+ scripts across all categories

    Deliverable:
        Full-featured scripting engine with protocol support.

PHASE 5 — POLISH AND ECOSYSTEM (Weeks 14-16)
    Goal: Production quality and script ecosystem.

    Tasks:
        - Write comprehensive documentation (API.md, SCRIPTING.md)
        - Write unit tests for all components
        - Write integration tests with real scripts
        - Performance profiling and optimization
        - Memory leak detection and fixing
        - Write 20+ additional scripts (total 50+)
        - Write script development guide
        - Add script linting/validation tool
        - Final security audit of sandbox
        - Cross-platform testing (macOS, Linux, FreeBSD)

    Deliverable:
        Production-ready NPE with 50+ scripts and full documentation.


================================================================================
SECTION 19: TESTING STRATEGY
================================================================================

UNIT TESTS:
    test_engine.c          Engine init/shutdown, config handling
    test_loader.c          Script loading, metadata parsing
    test_runtime.c         Lua state creation, library registration
    test_sandbox.c         Verify dangerous functions removed
    test_scheduler.c       Thread pool, work queue operations
    test_registry.c        Script database operations
    test_context.c         Host/port context pushing
    test_result.c          Result collection and formatting
    test_lib_net.c         Socket operations (mock server)
    test_lib_http.c        HTTP client (mock server)
    test_lib_dns.c         DNS resolution (mock)
    test_lib_json.c        JSON parse/encode
    test_lib_string.c      String utilities
    test_lib_crypto.c      Hash and encryption

INTEGRATION TESTS:
    test_scripts.c         Run real scripts against mock services
    test_concurrency.c     Multiple scripts running in parallel
    test_memory.c          Memory limit enforcement
    test_timeout.c         Timeout enforcement
    test_errors.c          Error recovery and graceful failure

SCRIPT TESTS:
    Each script should have a companion test that:
        1. Sets up a mock service
        2. Runs the script against it
        3. Validates the output format
        4. Checks error handling


================================================================================
SECTION 20: FUTURE ROADMAP
================================================================================

VERSION 1.1:
    - Script auto-update mechanism
    - Community script repository
    - Script signing and verification
    - Performance dashboard

VERSION 1.2:
    - Plugin system for C-native extensions
    - Distributed scanning with multiple NetPeek instances
    - Real-time script output streaming
    - Web-based script editor

VERSION 2.0:
    - Alternative scripting languages (Python, JavaScript bindings)
    - Machine learning integration for anomaly detection
    - Automated vulnerability correlation
    - Report generation (PDF, HTML)


================================================================================
END OF PLAN
================================================================================

SUMMARY:
    Engine Name:     NPE (NetPeek Extension Engine)
    Language:        Lua (system-installed, linked via headers)
    Extension:       .npe
    Architecture:    Threaded scheduler + per-script Lua VM + C libraries
    Security:        Sandboxed Lua + resource limits + restricted I/O
    Libraries:       15 core libraries + 12 protocol libraries
    Scripts:         50+ across 8 categories
    Output:          Integrated with NetPeek text/JSON/CSV output
    Build:           System Lua via pkg-config, no bundled source
    Timeline:        16 weeks to production quality

================================================================================
