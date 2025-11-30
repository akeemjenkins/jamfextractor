# v1.0.1 - Initial Release

**Jamf FileVault Recovery Key Extractor**

A cross-platform Go tool for extracting FileVault recovery keys from Jamf Pro.

## Features

- Extract FileVault recovery keys from all computers or specific IDs
- Modern Jamf Pro API with bearer token authentication
- Cross-platform binaries (macOS ARM64/Intel, Linux, Windows)
- CSV report generation with comprehensive audit logging
- Professional CLI with Cobra framework

## Usage

```bash
# Process all computers
./jamf-extractor all -u "https://your-jamf.com/" -n "user" -p "pass"

# Process specific computers from file
./jamf-extractor file ids.txt -u "https://your-jamf.com/" -n "user" -p "pass"
```

## Downloads

- **macOS Apple Silicon**: `jamf-extractor-darwin-arm64`
- **macOS Intel**: `jamf-extractor-darwin-amd64`
- **Linux x86_64**: `jamf-extractor-linux-amd64`
- **Windows x86_64**: `jamf-extractor-windows-amd64.exe`

## Credits

Based on the original script by [Rich Trouton (Der Flounder)](https://derflounder.wordpress.com/2023/01/25/using-the-jamf-pro-api-to-retrieve-filevault-personal-recovery-keys/).

## Security

- All dependencies verified and secure
- No critical vulnerabilities found
- Comprehensive audit logging for compliance
- SHA256 checksums provided for verification

## Requirements

- Go 1.24+ (for building from source)
- Jamf Pro API access with appropriate permissions
- Network connectivity to Jamf Pro server

