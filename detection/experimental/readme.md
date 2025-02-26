# Experimental

A collection of experimental scripts and tools with limited testing. These are primarily for demonstration, learning, and experimental purposes.

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK!**

The contents of this folder are:
- Experimental in nature
- Provided with limited testing
- Not officially supported
- May contain bugs or unexpected behaviors
- Not recommended for production environments without thorough testing

## Overview

This repository contains various experimental scripts and tools, including:

- PowerShell scripts for Microsoft 365 security configurations
- Security monitoring and detection tools
- Expanded cloud logging implementations based on CISA playbooks
- Other experimental utilities and code samples

## Repository Contents

- **MS-Cloud-Logs** - Scripts for enabling and analyzing Microsoft expanded cloud logs, based on CISA recommendations
  - `Enable-ExpandedCloudLogs.ps1` - Enables enhanced cloud logging capabilities
  - `Detect-SuspiciousActivity.ps1` - Analyzes logs for potential security incidents

*Additional scripts and tools will be added over time.*

## Requirements

Most scripts in this repository require specific modules or permissions. Check the header documentation in individual scripts for detailed requirements.

Common requirements include:
- PowerShell 5.1 or higher
- Exchange Online PowerShell module
- Microsoft 365 admin permissions
- Various Microsoft 365 service-specific permissions

## Usage Notes

1. **Always review scripts** before running them in your environment
2. Test in a non-production environment first
3. Many scripts require administrative privileges
4. Some functionality may break with Microsoft service updates
5. Error handling may be limited

## Contributions

Contributions are welcome but will be reviewed thoroughly before acceptance. Please note that all contributions will be considered experimental and subject to the same disclaimers.

## Known Issues

- Some scripts may contain parser errors or require modifications to run in different environments
- PowerShell operator compatibility issues may exist in more complex scripts
- Authentication methods may need updates as Microsoft evolves their security practices

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

*This repository is maintained on a best-effort basis. Issues and pull requests may not be addressed immediately.*
