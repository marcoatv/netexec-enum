# netexec-enum
An advanced Python automation tool for penetration testers that streamlines NetExec credential validation and enumeration across multiple targets and protocols.

# NetExec Enhanced Enumeration Script

An advanced automation tool for penetration testers that streamlines NetExec credential validation and enumeration across multiple targets and protocols.

## Features

- **Multi-Target Support**: Single IPs, CIDR notation, comma-separated lists, or target files
- **Intelligent Credential Validation**: Batch testing with `--continue-on-success` before enumeration
- **Multiple Authentication Methods**: Password lists, hash files, or single credentials
- **Comprehensive Protocol Coverage**: SMB, LDAP, WinRM, SSH, MSSQL, WMI, FTP, VNC, RDP
- **Advanced Enumeration**: Automatic admin privilege detection and specialized modules
- **Robust Error Handling**: Gracefully handles NetExec internal errors
- **Detailed Reporting**: Structured logs and executive summaries

## Installation

### Prerequisites
##### Install NetExec
pip install netexec

# Clone this repository
git clone https://github.com/marcoatv/netexec-enum.git

## Usage

### Basic Examples

#### Single target with credentials
`python3 netexec-enum.py -i 192.168.1.100 -u admin -p password123`

#### Multiple targets with wordlists
`python3 netexec-enum.py -i "192.168.1.1,192.168.1.5,192.168.1.10" -u users.txt -p passwords.txt`

#### CIDR range with hash authentication
`python3netexec-enum.py -i 192.168.1.0/24 -u users.txt -H hashes.txt`

#### Target file with local authentication
`python3 netexec-enum.pyy -i targets.txt -u admin -p password --local`

#### Credential validation only (no full enumeration)
`python3 netexec-enum.py -i 192.168.1.0/24 -u users.txt -p passwords.txt --validate-only`

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --ip` | Target IP(s): single IP, comma-separated, CIDR, or file path |
| `-u, --user` | Username or path to username wordlist |
| `-p, --pass` | Password or path to password wordlist |
| `-H, --hash` | Hash value or path to hash file |
| `--local` | Use local authentication mode |
| `--validate-only` | Only validate credentials, skip enumeration |

## Input Formats

### Target Formats
#### Single IP
`-i 192.168.1.100`

#### Comma-separated IPs
`-i "192.168.1.1,192.168.1.5,10.0.0.1"`

#### CIDR notation
`-i 192.168.1.0/24`

#### Target file (one IP per line)
`-i targets.txt`

### Credential Formats
#### Username/password files (one per line)
- users.txt
- admin
- passwords.txt:
- password123

#### Hash file (supports multiple formats)
- hashes.txt
- e728ecbadfb02f51ce8eed753f3ff3fd
- admin:e728ecbadfb02f51ce8eed753f3ff3fd
- user:1001:e728ecbadfb02f51ce8eed753f3ff3fd

## Enumeration Modules

#### SMB Protocol
- Share enumeration (`--shares`)
- User enumeration (`--users`, `--groups`)
- Computer information (`--computer`)
- Session information (`--loggedon-users`, `--sessions`)
- Advanced modules (`spider_plus`, `lsassy` for admins)

#### LDAP Protocol
- Domain enumeration (`--users`, `--groups`)
- BloodHound collection (`--bloodhound`)
- Kerberoasting (`--kerberoasting`)
- AS-REP roasting (`--asreproast`)
- ADCS enumeration (for admins)

#### WinRM/SSH/Others
- Command execution capabilities
- Privilege enumeration
- System information gathering

## Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems.
