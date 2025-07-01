#!/usr/bin/env python3

import argparse
import json
import sys
from colorama import init, Fore, Style
from ipti import IPTI

# Initialize colorama for cross-platform color support
init()

def generate_text_report(result: dict) -> str:
    """Generate a formatted text report from the IPTI result."""
    
    # Define platform names for display
    platform_names = {
        "abuseipdb": "AbuseIPDB",
        "virustotal": "VirusTotal", 
        "threatbook": "Threatbook IO",
        "alienvault": "Alienvault OTX"
    }
    
    # Generate platform results section
    platform_results = []
    for platform, is_malicious in result["malicious_report"].items():
        status = "SAFE" if not is_malicious else "MALICIOUS"
        if not is_malicious:
            # Green checkmark for safe
            icon = f"{Fore.GREEN}✓{Style.RESET_ALL}"
            status_colored = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        else:
            # Red X for malicious
            icon = f"{Fore.RED}✗{Style.RESET_ALL}"
            status_colored = f"{Fore.RED}{status}{Style.RESET_ALL}"
        platform_results.append(f"  {platform_names[platform]}: {icon} {status_colored}")
    
    # Determine overall assessment
    overall_status = "SAFE" if result["is_safe"] else "MALICIOUS"
    if result["is_safe"]:
        # Green checkmark for overall safe
        overall_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}"
        overall_status_colored = f"{Fore.GREEN}{overall_status}{Style.RESET_ALL}"
    else:
        # Red X for overall malicious
        overall_icon = f"{Fore.RED}✗{Style.RESET_ALL}"
        overall_status_colored = f"{Fore.RED}{overall_status}{Style.RESET_ALL}"
    
    report = f"""=== IP Threat Intelligence Report ===
IP Address: {result['ip']}
Check Date: {result['check_date']}
Max Age (days): {result['max_age_in_days']}
Score Threshold: {result['score_threshold']}
User Threshold: {result['user_threshold']}
Safe Ratio: {result['safe_ratio']:.2f}

Platform Results:
{chr(10).join(platform_results)}

Overall Assessment:
{overall_icon} IP is considered {overall_status_colored}
Platforms considered: {result['platforms_considered']}
Platforms flagged as safe: {result['platforms_flagged_as_safe']}"""
    
    return report


def generate_summary_report(results: list) -> str:
    """Generate a summary report for multiple IP addresses."""
    
    total_ips = len(results)
    safe_ips = sum(1 for result in results if result["is_safe"])
    malicious_ips = total_ips - safe_ips
    
    summary = f"""=== IP Threat Intelligence Summary Report ===
Total IPs Checked: {total_ips}
Safe IPs: {Fore.GREEN}{safe_ips}{Style.RESET_ALL}
Malicious IPs: {Fore.RED}{malicious_ips}{Style.RESET_ALL}

Detailed Results:
"""
    
    for i, result in enumerate(results, 1):
        status_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if result["is_safe"] else f"{Fore.RED}✗{Style.RESET_ALL}"
        status_text = f"{Fore.GREEN}SAFE{Style.RESET_ALL}" if result["is_safe"] else f"{Fore.RED}MALICIOUS{Style.RESET_ALL}"
        summary += f"{i}. {status_icon} {result['ip']} - {status_text}\n"
    
    return summary


def print_banner():
    banner = f"""{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  ██╗██████╗ ████████╗██╗    IP Threat Intelligence Tool      ║
║  ██║██╔══██╗╚══██╔══╝██║    Version: v1.0.0                  ║
║  ██║██████╔╝   ██║   ██║    GitHub: bayufedra                ║
║  ██║██╔═══╝    ██║   ██║                                     ║
║  ██║██║        ██║   ██║                                     ║
║  ╚═╝╚═╝        ╚═╝   ╚═╝                                     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def main():
    """Main function with command-line argument parsing."""
    print_banner()

    parser = argparse.ArgumentParser(
        description="IP Threat Intelligence Tool - Check multiple IP addresses for threats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --ip 192.168.1.1 10.0.0.1 8.8.8.8 --output-file report.txt --output-format text
  python main.py -i 8.8.8.8 1.1.1.1 -o report.json -f json
  python main.py --list ips.txt --output-file report.txt --output-format text
  python main.py -l ips.txt -o report.json -f json
  python main.py --ip 10.0.0.1 192.168.1.100 --max-age 60 --max-score 50 --max-user 5 --safe-ratio 0.8
  python main.py -i 127.0.0.1  # Single IP still works
        """
    )
    
    # Create a mutually exclusive group for IP input methods
    ip_group = parser.add_mutually_exclusive_group(required=True)
    
    # Option 1: Individual IP addresses
    ip_group.add_argument(
        "--ip", "-i",
        nargs="+",  # Accept one or more IP addresses
        help="IP address(es) to check (can specify multiple)"
    )
    
    # Option 2: List of IP addresses from file
    ip_group.add_argument(
        "--list", "-l",
        help="File containing list of IP addresses (one per line)"
    )
    
    # Optional arguments
    parser.add_argument(
        "--max-age", "-a",
        type=int,
        default=30,
        help="Maximum age in days for threat data (default: 30)"
    )
    
    parser.add_argument(
        "--max-user", "-u", 
        type=int,
        default=3,
        help="Maximum number of users threshold (default: 3)"
    )
    
    parser.add_argument(
        "--max-score", "-s",
        type=int,
        default=30,
        help="Maximum score threshold (default: 30)"
    )
    
    parser.add_argument(
        "--safe-ratio", "-r",
        type=float,
        default=0.75,
        help="Safe ratio threshold (default: 0.75)"
    )
    
    parser.add_argument(
        "--output-file", "-o",
        help="Output file path (optional)"
    )
    
    parser.add_argument(
        "--output-format", "-f",
        choices=["json", "text"],
        default="text",
        help="Output format for terminal and file (default: text)"
    )
    
    parser.add_argument(
        "--summary-only", "-S",
        action="store_true",
        help="Show only summary report (for multiple IPs)"
    )
    
    args = parser.parse_args()
    
    # Determine which IP addresses to check
    ips_to_check = []
    
    if args.ip:
        # Use IPs provided directly via command line
        ips_to_check = args.ip
    elif args.list:
        # Read IPs from file
        try:
            with open(args.list, 'r') as f:
                ips_to_check = [line.strip() for line in f if line.strip()]
            if not ips_to_check:
                print(f"No IP addresses found in file: {args.list}", file=sys.stderr)
                sys.exit(1)
        except FileNotFoundError:
            print(f"File not found: {args.list}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file {args.list}: {e}", file=sys.stderr)
            sys.exit(1)
    
    try:
        results = []
        
        # Process each IP address
        for ip in ips_to_check:
            try:
                print(f"[INFO] Checking IP: {ip}", file=sys.stderr)
                
                # Create IPTI instance and check the IP
                ipti = IPTI(
                    ip=ip,
                    max_age_in_days=args.max_age,
                    user_threshold=args.max_user,
                    score_threshold=args.max_score,
                    safe_ratio=args.safe_ratio
                )
                
                result = ipti.is_malicious()
                results.append(result)
                
            except KeyError as e:
                print(f"Error: API rate limit exceeded or invalid API token. Please check your API keys and try again later.", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error checking IP {ip}: {e}. This may be due to API issues, network problems, or invalid API configuration.", file=sys.stderr)
                # Continue with other IPs even if one fails
                continue
        
        if not results:
            print("No IP addresses were successfully checked.", file=sys.stderr)
            sys.exit(1)
        
        # Output to terminal
        if args.output_format == "json":
            if len(results) == 1:
                print(json.dumps(results[0], indent=2))
            else:
                print(json.dumps(results, indent=2))
        else:  # text format
            if len(results) == 1:
                print(generate_text_report(results[0]))
            else:
                if args.summary_only:
                    print(generate_summary_report(results))
                else:
                    # Show detailed reports for each IP
                    for i, result in enumerate(results, 1):
                        print(f"\n{'='*60}")
                        print(f"IP {i} of {len(results)}")
                        print(generate_text_report(result))
                    
                    # Show summary at the end
                    print(f"\n{'='*60}")
                    print(generate_summary_report(results))
        
        # Output to file if specified
        if args.output_file:
            try:
                with open(args.output_file, 'w') as f:
                    if args.output_format == "json":
                        if len(results) == 1:
                            json.dump(results[0], f, indent=2)
                        else:
                            json.dump(results, f, indent=2)
                    else:  # text format
                        if len(results) == 1:
                            f.write(generate_text_report(results[0]))
                        else:
                            if args.summary_only:
                                f.write(generate_summary_report(results))
                            else:
                                # Write detailed reports for each IP
                                for i, result in enumerate(results, 1):
                                    f.write(f"\n{'='*60}\n")
                                    f.write(f"IP {i} of {len(results)}\n")
                                    f.write(generate_text_report(result))
                                
                                # Write summary at the end
                                f.write(f"\n{'='*60}\n")
                                f.write(generate_summary_report(results))
                
                print(f"\nReport saved to: {args.output_file}")
            except Exception as e:
                print(f"Error writing to file {args.output_file}: {e}", file=sys.stderr)
                sys.exit(1)
                
    except Exception as e:
        print(f"Error: {e}. Please check your API configuration and network connection.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
