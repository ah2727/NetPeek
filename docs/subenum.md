# Subdomain Enumeration (`subenum`)

NetPeek provides a dedicated subdomain discovery command:

```bash
netpeek subenum -d example.com
netpeek subenum -d example.com --ct --axfr --permute --json
netpeek subenum -d example.com -w data/wordlists/subdomains-top5000.txt --filter-alive
```

## Compatibility

The `dns` command remains available and maps to the same backend for subdomain-centric usage:

```bash
netpeek dns example.com --sub --json
```

## Flags

- `-d, --domain <domain>` target domain (repeatable)
- `-w, --wordlist <file>` custom wordlist
- `--builtin-wordlist` use built-in wordlist
- `-T, --threads <n>` worker count (default 32)
- `--timeout <ms>` DNS timeout in milliseconds
- `--brute`, `--axfr`, `--ct`, `--reverse`, `--permute` technique toggles
- `--wildcard-detect` wildcard filtering
- `--json`, `--csv`, `--grep` output format
- `-o, --output <file>` write to file

## Output

Default output is a table with `SUBDOMAIN`, `IP ADDRESS`, and `SOURCE` columns.
Structured output (`--json`, `--csv`, `--grep`) is also available.
