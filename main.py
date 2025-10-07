#!/usr/bin/env python3
"""
Domain Discovery Tool
Finds domains and TLDs associated with an organization
Author:- Mohit_Negi
"""

import requests
import json
import dns.resolver
import whois
from datetime import datetime
import argparse
import time
from typing import List, Set, Dict
import re

class DomainDiscovery:
    def __init__(self, organization: str):
        self.organization = organization
        self.domains = set()
        self.subdomains = set()
        
    def search_crtsh(self, base_domain: str) -> Set[str]:
        """Search certificate transparency logs via crt.sh"""
        print(f"[*] Searching certificate transparency logs for {base_domain}...")
        domains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{base_domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple domains in one entry
                    for domain in name.split('\n'):
                        domain = domain.strip().lower()
                        if domain and not domain.startswith('*'):
                            domains.add(domain)
                print(f"[+] Found {len(domains)} domains from crt.sh")
            else:
                print(f"[-] crt.sh returned status code {response.status_code}")
                
        except Exception as e:
            print(f"[-] Error searching crt.sh: {e}")
            
        return domains
    
    def search_virustotal(self, domain: str, api_key: str = None) -> Set[str]:
        """Search VirusTotal for subdomains (requires API key)"""
        if not api_key:
            print("[!] VirusTotal API key not provided, skipping...")
            return set()
            
        print(f"[*] Searching VirusTotal for {domain}...")
        domains = set()
        
        try:
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain:
                        domains.add(subdomain.lower())
                print(f"[+] Found {len(domains)} domains from VirusTotal")
            else:
                print(f"[-] VirusTotal returned status code {response.status_code}")
                
        except Exception as e:
            print(f"[-] Error searching VirusTotal: {e}")
            
        return domains
    
    def search_hackertarget(self, domain: str) -> Set[str]:
        """Search HackerTarget API for subdomains"""
        print(f"[*] Searching HackerTarget for {domain}...")
        domains = set()
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain:
                            domains.add(subdomain)
                print(f"[+] Found {len(domains)} domains from HackerTarget")
            else:
                print(f"[-] HackerTarget returned status code {response.status_code}")
                
        except Exception as e:
            print(f"[-] Error searching HackerTarget: {e}")
            
        return domains
    
    def check_common_tlds(self, base_name: str) -> Set[str]:
        """Check common TLD variations"""
        print(f"[*] Checking common TLD variations for {base_name}...")
        common_tlds = [
            'com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev',
            'tech', 'online', 'site', 'website', 'space', 'store',
            'cloud', 'host', 'info', 'biz', 'me', 'tv', 'cc',
            'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in'
        ]
        
        active_domains = set()
        
        for tld in common_tlds:
            domain = f"{base_name}.{tld}"
            try:
                # Try DNS resolution
                dns.resolver.resolve(domain, 'A')
                active_domains.add(domain)
                print(f"[+] Active: {domain}")
                time.sleep(0.1)  # Rate limiting
            except:
                pass
                
        return active_domains
    
    def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for a domain"""
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'org': w.org,
                'emails': w.emails
            }
        except Exception as e:
            return {'domain': domain, 'error': str(e)}
    
    def discover(self, base_domains: List[str], vt_api_key: str = None):
        """Main discovery method"""
        print(f"\n{'='*60}")
        print(f"Domain Discovery for: {self.organization}")
        print(f"{'='*60}\n")
        
        all_domains = set()
        
        # Search for each base domain
        for base_domain in base_domains:
            print(f"\n[*] Analyzing base domain: {base_domain}\n")
            
            # Certificate transparency
            domains = self.search_crtsh(base_domain)
            all_domains.update(domains)
            
            time.sleep(1)  # Rate limiting
            
            # HackerTarget
            domains = self.search_hackertarget(base_domain)
            all_domains.update(domains)
            
            time.sleep(1)  # Rate limiting
            
            # VirusTotal (if API key provided)
            if vt_api_key:
                domains = self.search_virustotal(base_domain, vt_api_key)
                all_domains.update(domains)
                time.sleep(1)
        
        # Extract base names and check TLD variations
        base_names = set()
        for domain in list(all_domains):
            # Extract base name (e.g., 'google' from 'google.com')
            parts = domain.split('.')
            if len(parts) >= 2:
                base_names.add(parts[0])
        
        # Check TLD variations for main organization name
        org_base = self.organization.lower().replace(' ', '').replace('inc', '').replace('llc', '').replace('.', '').strip()
        base_names.add(org_base)
        
        for base in list(base_names)[:3]:  # Limit to avoid too many requests
            tld_domains = self.check_common_tlds(base)
            all_domains.update(tld_domains)
        
        self.domains = all_domains
        return all_domains
    
    def export_results(self, filename: str = None):
        """Export results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"domains_{self.organization.replace(' ', '_')}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"Domain Discovery Results\n")
            f.write(f"Organization: {self.organization}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total domains found: {len(self.domains)}\n")
            f.write(f"\n{'='*60}\n\n")
            
            for domain in sorted(self.domains):
                f.write(f"{domain}\n")
        
        print(f"\n[+] Results exported to: {filename}")
        return filename
    
    def print_summary(self):
        """Print summary of findings"""
        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}")
        print(f"Organization: {self.organization}")
        print(f"Total domains found: {len(self.domains)}")
        print(f"\nDomains by TLD:")
        
        # Group by TLD
        tld_counts = {}
        for domain in self.domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                tld_counts[tld] = tld_counts.get(tld, 0) + 1
        
        for tld, count in sorted(tld_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  .{tld}: {count}")
        
        print(f"\n[*] Full list of domains:")
        for domain in sorted(self.domains):
            print(f"  {domain}")


def main():
    parser = argparse.ArgumentParser(
        description='Discover domains and TLDs associated with an organization'
    )
    parser.add_argument('organization', help='Organization name (e.g., "Google Inc")')
    parser.add_argument('-d', '--domains', nargs='+', 
                       help='Base domains to search (e.g., google.com youtube.com)',
                       required=True)
    parser.add_argument('-v', '--virustotal-key', 
                       help='VirusTotal API key (optional)')
    parser.add_argument('-o', '--output', 
                       help='Output filename (optional)')
    
    args = parser.parse_args()
    
    # Create discovery instance
    discovery = DomainDiscovery(args.organization)
    
    # Run discovery
    discovery.discover(args.domains, args.virustotal_key)
    
    # Print summary
    discovery.print_summary()
    
    # Export results
    if args.output:
        discovery.export_results(args.output)
    else:
        discovery.export_results()


if __name__ == "__main__":
    main()
