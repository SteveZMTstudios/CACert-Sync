# CACert-Sync Project Instructions

## Project Overview
This is a CA certificate collection and synchronization system that aggregates root CA certificates from multiple authoritative sources (Ubuntu, Firefox/Mozilla, Windows, Python certifi) and publishes them via GitHub Pages. The system runs automatically via GitHub Actions annually and handles certificate revocation through blacklists.

## Architecture & Key Components

### Core Scripts (`scripts/`)
- **`sync_certificates.py`**: Main orchestration script that collects certificates from all sources, processes them (deduplicate, validate, check revocation), and generates the HTML index
- **`extract_mozilla_certdata.py`**: Parses Mozilla's `certdata.txt` format (multiline octal encoding) to extract individual certificates
- **`cacert-cli.py`**: CLI wrapper providing `sync`, `test`, and `setup` commands - delegates to other scripts
- **`test_certificate_sync.py`**: Creates sample certificates and tests HTML generation locally

### Data Flow
1. **Collection**: Each source collector (`collect_*_certs()` functions) downloads certificates to `temp/<source>/`
2. **Revocation Check**: `update_revoked_certificates()` fetches blacklists from Mozilla CCADB, Windows STL files, and Google CRLSets, storing SHA-1/SHA-256 fingerprints in `blacklist.txt`
3. **Processing**: `process_and_store_certs()` validates certificates (must be self-signed root CAs), checks against blacklist, deduplicates by fingerprint, and normalizes filenames
4. **Output**: Final certificates stored in `certs/`, HTML generated from `templates/index.html` to `index.html`

### Certificate Processing Conventions
- **Filename normalization**: Uses certificate CN/O + 8-char fingerprint suffix (e.g., `DigiCert_Global_Root_CA_1a2b3c4d.crt`)
- **Blacklist format**: `<type>:<fingerprint>` where type is `sha1` or `sha256` (also supports legacy format without type prefix)
- **Self-signed validation**: Only accepts root CAs verified by `openssl verify -CAfile <cert> <cert>`
- **Duplicate detection**: Tracks SHA-1 fingerprints in a set to skip duplicates across sources

## Critical System Dependencies
The project requires these system tools (installed via `apt-get` in GitHub Actions):
- `openssl`: Certificate validation, fingerprint extraction, format conversion
- `wget`/`curl`: Downloading certificates and HTML pages
- `cabextract`: Extracting Windows `.cab` files containing STL certificate lists
- `ca-certificates`: Ubuntu system certificates

## Development Workflows

### Local Development Setup
```bash
./install.sh  # Creates venv, installs Python deps, runs setup
source venv/bin/activate
sudo python scripts/cacert-cli.py sync  # Requires root for /usr/share/ca-certificates access
```

### Testing Without Network Access
Use `test_certificate_sync.py` which creates sample certificates and tests HTML generation:
```bash
python scripts/test_certificate_sync.py
```

### Adding a New Certificate Source
1. Create a `collect_<source>_certs(verbose: bool) -> List[Path]` function in `sync_certificates.py`
2. Download certificates to `SOURCES_DIR["<source>"]` (defined in constants)
3. Return list of `.crt` file paths
4. Add call to new function in `main()` and aggregate results into `collected_certs`
5. For high-volume ecosystems (e.g. Mozilla), prefer single-bundle or metadata file parsing over per-cert page scraping to avoid 429 rate limits.

### Debugging Certificate Collection Issues
- Set `verbose=True` to stream `openssl` output and wget/curl diagnostics
- Check `blacklist.txt` if apparently valid roots are skipped (ensure fingerprint type + value)
- Enable `logging.DEBUG` for deeper parsing traces
- If Mozilla certdata parsing fails (zero output), confirm availability of `certdata.txt` and fallback CCADB HTML logic; inspect `temp/mozilla_ca_list.html` only when fallback engaged
- Rate limit mitigation: current flow first tries `collect_mozilla_certdata_certs`; only falls back to CCADB if empty. Avoid adding loops that hammer crt.sh.

## GitHub Actions Specifics
- **Schedule**: Runs yearly on June 15 at 16:04 UTC (`cron: '4 16 15 6 *'`) - the DMC reference comment "I AM THE STORM THAT IS APPROACHING" is intentional
- **Permissions**: Requires `contents: write` to commit certificate updates and create releases
- **SSH Deploy Key**: Uses `secrets.DEPLOY_KEY` for git push (stored as `~/.ssh/id_ed25519`)
- **Artifacts**: Uploads compressed logs (`logs.tar.gz`) with 60-day retention for debugging
- **Manual trigger**: Can be dispatched manually via GitHub UI (`workflow_dispatch`)

## HTML Generation Pattern
- Template is `templates/index.html` with placeholders: `{{LAST_UPDATED}}`, `{{CERTIFICATE_COUNT}}`, `{{CERTIFICATE_LIST_REPLACED}}`
- Certificate list sorted alphabetically by display name (case-insensitive)
- Asset path fix: Replace `templates/assets/` → `assets/` in generated HTML
- Each certificate row includes CN, issuer O, expiry date, and download link

## Important Gotchas
1. **Root permissions**: Ubuntu certificate collection requires `sudo` for `/usr/share/ca-certificates/`
2. **Mozilla source strategy**: Prefer certdata.txt → fewer outbound requests; fallback CCADB HTML parsing only if certdata yields zero certificates
3. **Rate limiting**: Avoid iterative per-cert `crt.sh` scraping; no parallel bursts—single certdata download is intentional
4. **Windows STL files**: Check local `disallowedcert.stl` first; then download CAB; parse PKCS7 with `openssl pkcs7 -print_certs`
5. **Octal encoding**: certdata.txt contains `MULTILINE_OCTAL`; parsing done in `extract_mozilla_certdata.py`
6. **DN field parsing**: Quoted fields handled via custom `parse_dn_string()`; do not naïvely split on commas
7. **File permissions**: GitHub Actions stage adjusts perms (`755` dirs / `644` files) after sudo operations

## Configuration
- **`config.py`**: Defines certificate sources, blacklist sources, paths, and project metadata (mostly unused in current implementation - constants defined in scripts instead)
- **Blacklist sources**: Mozilla CA/Revoked_Certificates wiki, CCADB RemovedCACertificateReport
- **Update frequency**: Configured as "yearly" but actual schedule in workflow YAML

## When Modifying Certificate Logic
- Always validate with `openssl x509 -in <cert> -noout -text` after any format conversion
- Test against all four sources to ensure compatibility
- Update blacklist handling if adding new fingerprint types (e.g., SHA-384)
- Preserve both SHA-1 and SHA-256 fingerprints for backward compatibility
