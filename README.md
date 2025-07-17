# Chronicle SOAR - Harmony IOC Uploader

This script integrates with Check Point Harmony Endpoint API to upload IOCs from Chronicle SOAR. It authenticates using credentials stored in Azure Key Vault and supports multiple tenants.

## Features

- Extracts supported IOCs from Siemplify entities (IP, Domain, URL, Hash).
- Retrieves secrets from Azure Key Vault.
- Authenticates with Check Point Harmony API.
- Uploads IOCs per customer tenant.
- Logs results and handles errors gracefully.

## Setup

1. Copy `config.py.example` to `config.py` and fill in your credentials.
2. Add secrets to Azure Key Vault in the format: `id=<clientId> secret=<accessKey>`.
3. Run the script within a Chronicle SOAR environment.

## Supported Entities

- IP Address
- Domain
- URL (validated, excluding trailing `=`)
- File Hashes: SHA1, MD5 (SHA256 is skipped)

## Notes

- Make sure not to upload `config.py` to version control.
- Do not include actual secrets in the repo.

## License

MIT
