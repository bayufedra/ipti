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
    for platform, is_malicious in result["platforms"]["malicious_report"].items():
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
    
    # Add PTR information
    ptr_info = result.get('ptr', {})
    ptr_record = ptr_info.get('ptr', 'N/A')
    ptr_risk = ptr_info.get('ptr_risk', 'Unknown')
    
    # Add risk breakdown
    risk_breakdown = result.get('risk_breakdown', {})
    
    # Get PTR risk score from the scoring system
    ptr_risk_score = risk_breakdown.get('ptr_safe_ratio', 0.5)
    
    # Color code PTR risk
    if 'High Risk' in ptr_risk or 'Suspicious' in ptr_risk or 'Unusual PTR' in ptr_risk:
        ptr_risk_colored = f"{Fore.RED}{ptr_risk}{Style.RESET_ALL}"
    elif 'Medium Risk' in ptr_risk or 'Neutral' in ptr_risk or 'DNS Timeout' in ptr_risk or 'DNS Error' in ptr_risk:
        ptr_risk_colored = f"{Fore.YELLOW}{ptr_risk}{Style.RESET_ALL}"
    else:
        ptr_risk_colored = f"{Fore.GREEN}{ptr_risk}{Style.RESET_ALL}"

    # Add server information
    server_info = result.get('server_info', {})
    country = server_info.get('country', 'Unknown')
    city = server_info.get('city', 'Unknown')
    org = server_info.get('org', 'Unknown')
    isp = server_info.get('isp', 'Unknown')
    
    # Add risk assessment information
    risk_assessment = server_info.get('risk_assessment', {})
    geographic_risk = risk_assessment.get('geographic', {})
    provider_risk = risk_assessment.get('provider', {})
    overall_risk_level = risk_assessment.get('overall_risk_level', 'Unknown')
    
    # Color code risk levels
    if overall_risk_level == "High":
        risk_level_colored = f"{Fore.RED}{overall_risk_level}{Style.RESET_ALL}"
    elif overall_risk_level == "Medium":
        risk_level_colored = f"{Fore.YELLOW}{overall_risk_level}{Style.RESET_ALL}"
    else:
        risk_level_colored = f"{Fore.GREEN}{overall_risk_level}{Style.RESET_ALL}"
    
    # Add privacy information
    privacy = server_info.get('privacy', {})
    privacy_details = []
    
    # Display all privacy flags with their boolean values
    proxy_value = privacy.get('proxy', False)
    vpn_value = privacy.get('vpn', False)
    tor_value = privacy.get('tor', False)
    relay_value = privacy.get('relay', False)
    
    # Color code based on risk level
    proxy_color = f"{Fore.YELLOW}" if proxy_value else f"{Fore.GREEN}"
    vpn_color = f"{Fore.YELLOW}" if vpn_value else f"{Fore.GREEN}"
    tor_color = f"{Fore.RED}" if tor_value else f"{Fore.GREEN}"
    relay_color = f"{Fore.YELLOW}" if relay_value else f"{Fore.GREEN}"
    
    privacy_details.append(f"  Proxy: {proxy_color}{proxy_value}{Style.RESET_ALL}")
    privacy_details.append(f"  VPN: {vpn_color}{vpn_value}{Style.RESET_ALL}")
    privacy_details.append(f"  Tor: {tor_color}{tor_value}{Style.RESET_ALL}")
    privacy_details.append(f"  Relay: {relay_color}{relay_value}{Style.RESET_ALL}")
    
    privacy_status = "\n".join(privacy_details)
    
    # Get risk breakdown values
    platform_safe_ratio = risk_breakdown.get('platform_safe_ratio', 0)
    ptr_safe_ratio = risk_breakdown.get('ptr_safe_ratio', 0)
    server_safe_ratio = risk_breakdown.get('server_safe_ratio', 0)
    port_safe_ratio = risk_breakdown.get('port_safe_ratio', 0)
    comprehensive_safe_ratio = result.get('safe_ratio', 0)

    # Add port analysis information
    ports_data = result.get('ports', {})
    risk_analysis = ports_data.get('risk_analysis', {})
    ports_count = ports_data.get('ports_count', 0)
    port_risk_level = risk_analysis.get('risk_level', 'Unknown')
    
    # Get port categories for display
    port_categories = ports_data.get('port_categories', {})
    high_risk_services = risk_analysis.get('high_risk_services', 0)
    average_risk = risk_analysis.get('average_risk', 0.0)
    
    # Color code port risk level
    if port_risk_level == "High" or port_risk_level == "Critical":
        port_risk_colored = f"{Fore.RED}{port_risk_level}{Style.RESET_ALL}"
    elif port_risk_level == "Medium":
        port_risk_colored = f"{Fore.YELLOW}{port_risk_level}{Style.RESET_ALL}"
    else:
        port_risk_colored = f"{Fore.GREEN}{port_risk_level}{Style.RESET_ALL}"

    report = f"""=== IP Threat Intelligence Report ===
IP Address: {result['ip']}
Check Date: {result['check_date']}
Max Age (days): {result['platforms']['max_age_in_days']}
Score Threshold: {result['platforms']['score_threshold']}
User Threshold: {result['platforms']['user_threshold']}

=== Server Information ===
Country: {country}
City: {city}
Organization: {org}
ISP: {isp}
Privacy Information:
{privacy_status}

=== Risk Assessment ===
Geographic Risk: {geographic_risk.get('risk_level', 'Unknown')} - {geographic_risk.get('reason', 'Unknown')}
Provider Risk: {provider_risk.get('risk_level', 'Unknown')} - {provider_risk.get('reason', 'Unknown')}
Overall Risk Level: {risk_level_colored}

=== PTR Information ===
PTR Record: {ptr_record}
PTR Risk Assessment: {ptr_risk_colored}
PTR Risk Score: {ptr_risk_score:.3f}

=== Port Analysis ===
Total Open Ports: {ports_count}
Port Risk Level: {port_risk_colored}
Average Risk Score: {average_risk:.3f}
High Risk Services: {high_risk_services}
Port Categories:
  Web Services: {', '.join(map(str, port_categories.get('web_services', []))) if port_categories.get('web_services') else 'None'}
  Database Services: {', '.join(map(str, port_categories.get('database_services', []))) if port_categories.get('database_services') else 'None'}
  Mail Services: {', '.join(map(str, port_categories.get('mail_services', []))) if port_categories.get('mail_services') else 'None'}
  Remote Access: {', '.join(map(str, port_categories.get('remote_access', []))) if port_categories.get('remote_access') else 'None'}
  File Services: {', '.join(map(str, port_categories.get('file_services', []))) if port_categories.get('file_services') else 'None'}
  Other Services: {', '.join(map(str, port_categories.get('other_services', []))) if port_categories.get('other_services') else 'None'}

=== Platform Results ===
{chr(10).join(platform_results)}

=== Risk Breakdown ===
Platform Safe Ratio: {platform_safe_ratio:.2f}
PTR Safe Ratio: {ptr_safe_ratio:.2f}
Server Safe Ratio: {server_safe_ratio:.2f}
Port Safe Ratio: {port_safe_ratio:.2f}
Comprehensive Safe Ratio: {comprehensive_safe_ratio:.2f}

=== Overall Assessment ===
{overall_icon} IP is considered {overall_status_colored}
Platforms considered: {result['platforms']['platforms_considered']}
Platforms flagged as safe: {result['platforms']['platforms_flagged_as_safe']}
Comprehensive Safe Ratio: {comprehensive_safe_ratio:.3f}"""
    
    return report


def generate_summary_report(results: list) -> str:
    """Generate a summary report for multiple IP addresses."""
    
    total_ips = len(results)
    safe_ips = sum(1 for result in results if result["is_safe"])
    malicious_ips = total_ips - safe_ips
    
    # Calculate average safe ratio
    total_safe_ratio = sum(result.get('safe_ratio', 0) for result in results)
    avg_safe_ratio = total_safe_ratio / total_ips if total_ips > 0 else 0
    
    summary = f"""=== IP Threat Intelligence Summary Report ===
Total IPs Checked: {total_ips}
Safe IPs: {Fore.GREEN}{safe_ips}{Style.RESET_ALL}
Malicious IPs: {Fore.RED}{malicious_ips}{Style.RESET_ALL}
Average Safe Ratio: {avg_safe_ratio:.3f}

Detailed Results:
"""
    
    for i, result in enumerate(results, 1):
        status_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if result["is_safe"] else f"{Fore.RED}✗{Style.RESET_ALL}"
        status_text = f"{Fore.GREEN}SAFE{Style.RESET_ALL}" if result["is_safe"] else f"{Fore.RED}MALICIOUS{Style.RESET_ALL}"
        safe_ratio = result.get('safe_ratio', 0)
        
        # Add PTR information if available
        ptr_info = result.get('ptr', {})
        ptr_risk = ptr_info.get('ptr_risk', 'Unknown')
        
        # Add privacy information if available
        server_info = result.get('server_info', {})
        privacy = server_info.get('privacy', {})
        privacy_details = []
        
        proxy_value = privacy.get('proxy', False)
        vpn_value = privacy.get('vpn', False)
        tor_value = privacy.get('tor', False)
        relay_value = privacy.get('relay', False)
        
        privacy_details.append(f"Proxy:{proxy_value}")
        privacy_details.append(f"VPN:{vpn_value}")
        privacy_details.append(f"Tor:{tor_value}")
        privacy_details.append(f"Relay:{relay_value}")
        
        privacy_status = " ".join(privacy_details)
        
        summary += f"{i}. {status_icon} {result['ip']} - {status_text} (Safe Ratio: {safe_ratio:.3f}, PTR: {ptr_risk}, Privacy: {privacy_status})\n"
    
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
        description="IP Threat Intelligence Tool - Comprehensive IP threat analysis using multiple security platforms",
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
        help="Maximum score threshold (range 1-100, default: 30)"
    )
    
    parser.add_argument(
        "--safe-ratio", "-r",
        type=float,
        default=0.75,
        help="Safe ratio threshold (range 0.1-1.0, default: 0.75)"
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
            # Skip empty IPs
            if not ip or not ip.strip():
                print(f"[WARNING] Skipping empty IP address", file=sys.stderr)
                continue
                
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
                
                result = ipti.ipti_check()
                results.append(result)
                
            except KeyError as e:
                print(f"Error: API rate limit exceeded or invalid API token. Please check your API keys and try again later.", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                error_msg = str(e)
                if "Missing API keys" in error_msg:
                    print(f"Error: {error_msg}. Please check your .env file and ensure all required API keys are set.", file=sys.stderr)
                    sys.exit(1)
                else:
                    print(f"Error checking IP {ip}: {error_msg}. This may be due to API issues, network problems, or invalid API configuration.", file=sys.stderr)
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
                with open(args.output_file, 'w', encoding='utf-8') as f:
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
        print(f"Unexpected error: {e}. Please check your API configuration, network connection, and ensure all required dependencies are installed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
