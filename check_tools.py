#!/usr/bin/env python3
"""
Tool installation checker for Phase 2 external tools.

Checks if Subfinder, HTTPX, and Nuclei are installed and provides
installation instructions if any are missing.
"""
import sys
import shutil
from tools.external_tools import (
    check_tool_installation,
    print_installation_instructions,
    SubfinderWrapper,
    HTTPXWrapper,
    NucleiWrapper
)


def main():
    print("\n" + "="*70)
    print("BUG BOUNTY ARSENAL v2.0 - TOOL INSTALLATION CHECKER")
    print("="*70 + "\n")
    
    # Check all tools
    status = check_tool_installation()
    
    all_installed = all(status.values())
    
    if all_installed:
        print("\n✓ ALL TOOLS INSTALLED AND READY!\n")
        
        # Show versions
        print("Tool information:")
        for tool_name in ["subfinder", "httpx", "nuclei"]:
            binary = shutil.which(tool_name)
            if binary:
                print(f"  • {tool_name}: {binary}")
        
        print("\nYou can now use --recon mode:")
        print("  python main.py --recon example.com --consent")
        print("\n" + "="*70 + "\n")
        return 0
    
    else:
        missing = [name for name, installed in status.items() if not installed]
        print(f"\n✗ MISSING TOOLS: {', '.join(missing)}\n")
        print_installation_instructions()
        
        print("\nAfter installation, run this checker again to verify:")
        print("  python check_tools.py\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
