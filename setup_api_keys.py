#!/usr/bin/env python3
"""
Interactive API Keys Setup for Subfinder
==========================================
This script helps you configure API keys for Subfinder to get 3-5x more subdomains.

Top Free Providers (Recommended):
1. SecurityTrails - https://securitytrails.com/app/account (50 queries/month free)
2. Shodan - https://account.shodan.io/ (1 query credit free)
3. VirusTotal - https://www.virustotal.com/gui/my-apikey (4 requests/min free)
4. GitHub - https://github.com/settings/tokens (5000 requests/hour)
5. Censys - https://search.censys.io/account/api (250 queries/month free)

Usage:
    python setup_api_keys.py
"""

import os
import sys
import yaml
from pathlib import Path

# ANSI colors for pretty output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.OKCYAN}ℹ {text}{Colors.ENDC}")

def print_warning(text):
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

# Provider information with signup URLs and instructions
PROVIDERS = {
    "securitytrails": {
        "name": "SecurityTrails",
        "signup": "https://securitytrails.com/app/account",
        "free_tier": "50 queries/month",
        "instructions": "Sign up → Go to Account → API → Copy your API Key",
        "example": "securitytrails: [\"your_api_key_here\"]",
        "priority": 1
    },
    "shodan": {
        "name": "Shodan",
        "signup": "https://account.shodan.io/",
        "free_tier": "1 query credit",
        "instructions": "Sign up → Go to Account → Copy your API Key",
        "example": "shodan: [\"your_api_key_here\"]",
        "priority": 2
    },
    "virustotal": {
        "name": "VirusTotal",
        "signup": "https://www.virustotal.com/gui/my-apikey",
        "free_tier": "4 requests/min",
        "instructions": "Sign up → Go to My API Key → Copy your API Key",
        "example": "virustotal: [\"your_api_key_here\"]",
        "priority": 3
    },
    "github": {
        "name": "GitHub Personal Access Token",
        "signup": "https://github.com/settings/tokens",
        "free_tier": "5000 requests/hour",
        "instructions": "Go to Settings → Developer settings → Personal access tokens → Generate new token (classic) → No scopes needed",
        "example": "github: [\"ghp_your_token_here\"]",
        "priority": 4
    },
    "censys": {
        "name": "Censys",
        "signup": "https://search.censys.io/account/api",
        "free_tier": "250 queries/month",
        "instructions": "Sign up → Go to API → Copy your API ID and Secret (format: ID:SECRET)",
        "example": "censys: [\"api_id:api_secret\"]",
        "priority": 5
    },
    "chaos": {
        "name": "Chaos (ProjectDiscovery)",
        "signup": "https://cloud.projectdiscovery.io/",
        "free_tier": "Limited free access",
        "instructions": "Sign up at ProjectDiscovery Cloud → Get your API key",
        "example": "chaos: [\"your_api_key_here\"]",
        "priority": 6
    },
    "bufferover": {
        "name": "BufferOver",
        "signup": "https://tls.bufferover.run/",
        "free_tier": "Free (no registration needed for basic)",
        "instructions": "Free tier works without API key, but premium gives more results",
        "example": "bufferover: []",
        "priority": 7
    }
}

def get_config_path():
    """Get the Subfinder config file path."""
    config_dir = Path.home() / ".config" / "subfinder"
    config_file = config_dir / "provider-config.yaml"
    return config_dir, config_file

def load_current_config(config_file):
    """Load existing configuration."""
    if config_file.exists():
        with open(config_file, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def save_config(config_file, config):
    """Save configuration to file."""
    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    # Set secure permissions (600)
    os.chmod(config_file, 0o600)

def show_provider_info(provider_key):
    """Display information about a provider."""
    provider = PROVIDERS[provider_key]
    print(f"\n{Colors.BOLD}{provider['name']}{Colors.ENDC}")
    print(f"  📊 Free Tier: {Colors.OKGREEN}{provider['free_tier']}{Colors.ENDC}")
    print(f"  🔗 Signup: {Colors.OKCYAN}{provider['signup']}{Colors.ENDC}")
    print(f"  📝 Instructions: {provider['instructions']}")
    print(f"  💡 Format: {Colors.WARNING}{provider['example']}{Colors.ENDC}")

def configure_provider(provider_key, current_value):
    """Configure a single provider."""
    provider = PROVIDERS[provider_key]
    
    show_provider_info(provider_key)
    
    # Check if already configured
    if current_value and len(current_value) > 0 and current_value[0]:
        print(f"\n  {Colors.OKGREEN}✓ Currently configured{Colors.ENDC}")
        print(f"    Current key: {current_value[0][:10]}...{current_value[0][-4:]}")
        
        choice = input(f"\n  Update this key? [y/N]: ").strip().lower()
        if choice != 'y':
            return current_value
    
    print(f"\n  Options:")
    print(f"    1. Enter API key now")
    print(f"    2. Skip for now (you can add it later)")
    print(f"    3. Open signup page in browser")
    
    choice = input(f"\n  Your choice [1/2/3]: ").strip()
    
    if choice == '1':
        api_key = input(f"\n  Enter your {provider['name']} API key: ").strip()
        if api_key:
            return [api_key]
        else:
            print_warning("No key entered, skipping...")
            return []
    elif choice == '3':
        print_info(f"Opening {provider['signup']} in your browser...")
        os.system(f"xdg-open '{provider['signup']}' 2>/dev/null || open '{provider['signup']}' 2>/dev/null")
        print_info("After getting your API key, run this script again!")
        return []
    else:
        print_info("Skipped")
        return []

def interactive_setup():
    """Run interactive setup."""
    print_header("Subfinder API Keys Setup")
    
    print(f"{Colors.BOLD}Why setup API keys?{Colors.ENDC}")
    print("  • Get 3-5x more subdomains compared to passive sources")
    print("  • Access to premium subdomain databases")
    print("  • Better coverage for bug bounty reconnaissance")
    print("  • All recommended providers have free tiers!\n")
    
    config_dir, config_file = get_config_path()
    current_config = load_current_config(config_file)
    
    print_info(f"Config file: {config_file}")
    
    if not config_file.exists():
        print_warning("Config file doesn't exist yet - will be created")
    else:
        print_success("Found existing config file")
    
    # Sort providers by priority
    sorted_providers = sorted(PROVIDERS.items(), key=lambda x: x[1]['priority'])
    
    print(f"\n{Colors.BOLD}Let's configure the top providers!{Colors.ENDC}")
    print("(You can always add more later by editing ~/.config/subfinder/provider-config.yaml)\n")
    
    new_config = current_config.copy()
    configured_count = 0
    
    for provider_key, provider_info in sorted_providers[:5]:  # Top 5 providers
        print(f"\n{Colors.BOLD}[{provider_info['priority']}/5] {provider_info['name']}{Colors.ENDC}")
        
        current_value = current_config.get(provider_key, [])
        result = configure_provider(provider_key, current_value)
        
        if result and len(result) > 0 and result[0]:
            new_config[provider_key] = result
            configured_count += 1
            print_success(f"{provider_info['name']} configured!")
        else:
            new_config[provider_key] = []
    
    # Ensure all other providers exist in config (empty)
    for provider_key in current_config:
        if provider_key not in new_config:
            new_config[provider_key] = current_config[provider_key]
    
    # Save configuration
    if configured_count > 0:
        print(f"\n{Colors.BOLD}Saving configuration...{Colors.ENDC}")
        save_config(config_file, new_config)
        print_success(f"Configuration saved to {config_file}")
        print_info(f"File permissions: 600 (secure)")
        
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}✓ Setup Complete!{Colors.ENDC}")
        print(f"\n  Configured providers: {Colors.BOLD}{configured_count}/5{Colors.ENDC}")
        print(f"\n  {Colors.BOLD}Next steps:{Colors.ENDC}")
        print(f"    1. Test with: python main.py --recon example.com --consent")
        print(f"    2. Add more API keys later by editing: {config_file}")
        print(f"    3. Or run this script again: python setup_api_keys.py")
    else:
        print_warning("\nNo API keys were configured.")
        print_info("Subfinder will still work using passive sources only (fewer results)")
    
    print()

def show_current_config():
    """Display current configuration status."""
    print_header("Current API Keys Configuration")
    
    config_dir, config_file = get_config_path()
    
    if not config_file.exists():
        print_warning("No configuration file found")
        print_info(f"Expected location: {config_file}")
        print_info("Run 'python setup_api_keys.py' to create it")
        return
    
    current_config = load_current_config(config_file)
    
    print(f"Config file: {Colors.OKCYAN}{config_file}{Colors.ENDC}\n")
    
    configured = []
    not_configured = []
    
    for provider_key, provider_info in sorted(PROVIDERS.items(), key=lambda x: x[1]['priority']):
        value = current_config.get(provider_key, [])
        if value and len(value) > 0 and value[0]:
            configured.append((provider_key, provider_info['name']))
        else:
            not_configured.append((provider_key, provider_info['name']))
    
    if configured:
        print(f"{Colors.OKGREEN}{Colors.BOLD}✓ Configured Providers ({len(configured)}):{Colors.ENDC}")
        for key, name in configured:
            value = current_config[key][0]
            masked_value = f"{value[:10]}...{value[-4:]}" if len(value) > 14 else value
            print(f"  • {name}: {masked_value}")
    else:
        print(f"{Colors.WARNING}No providers configured yet{Colors.ENDC}")
    
    if not_configured:
        print(f"\n{Colors.BOLD}Not Configured ({len(not_configured)}):{Colors.ENDC}")
        for key, name in not_configured[:5]:  # Show top 5
            print(f"  • {name} - {PROVIDERS[key]['signup']}")
        if len(not_configured) > 5:
            print(f"  ... and {len(not_configured) - 5} more")
    
    print(f"\n{Colors.BOLD}Commands:{Colors.ENDC}")
    print(f"  • Configure more: python setup_api_keys.py")
    print(f"  • Edit manually: nano {config_file}")
    print()

def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] in ['--status', '-s']:
        show_current_config()
    elif len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print(__doc__)
        print(f"\n{Colors.BOLD}Commands:{Colors.ENDC}")
        print(f"  python setup_api_keys.py           Run interactive setup")
        print(f"  python setup_api_keys.py --status  Show current configuration")
        print(f"  python setup_api_keys.py --help    Show this help")
        print()
    else:
        interactive_setup()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Setup cancelled by user{Colors.ENDC}\n")
        sys.exit(0)
    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)
