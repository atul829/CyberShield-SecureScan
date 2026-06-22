#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCI - Target Complexity Index
Smart scan planner for CyberShield
"""

import re
import json
from typing import Dict, List, Any

class TCI:
    """
    Target Complexity Index (TCI) calculator.
    Analyzes target attributes and recommends optimal scan plan.
    """
    
    def __init__(self):
        self.tci_score = 0
        self.factors = {}
        self.plan = []
        self.severity_levels = {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20
        }
    
    def analyze_target(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main method: Analyze target and generate scan plan.
        
        Args:
            scan_data: Nmap scan results (parsed)
            
        Returns:
            Dict with tci_score, factors, and recommended plan
        """
        self.tci_score = 0
        self.factors = {}
        self.plan = []
        
        # Extract target info
        open_ports = self._get_open_ports(scan_data)
        services = self._get_services(scan_data)
        hostnames = self._get_hostnames(scan_data)
        
        # Calculate TCI based on various factors
        self._analyze_port_count(open_ports)
        self._analyze_service_types(services)
        self._analyze_web_services(services)
        self._analyze_auth_services(services)
        self._analyze_hostname_complexity(hostnames)
        
        # Generate scan plan
        self._generate_plan()
        
        return {
            'tci_score': self.tci_score,
            'factors': self.factors,
            'recommended_plan': self.plan,
            'severity': self._get_severity_label()
        }
    
    def _get_open_ports(self, scan_data: Dict[str, Any]) -> List[int]:
        """Extract open ports from scan data"""
        ports = []
        for host in scan_data.get('hosts', []):
            for p in host.get('ports', []):
                if p.get('state') == 'open':
                    ports.append(p.get('portid'))
        return sorted(set(ports))
    
    def _get_services(self, scan_data: Dict[str, Any]) -> Dict[int, str]:
        """Extract service names from scan data"""
        services = {}
        for host in scan_data.get('hosts', []):
            for p in host.get('ports', []):
                if p.get('state') == 'open':
                    svc = p.get('service', {}).get('name', 'unknown')
                    services[p.get('portid')] = svc
        return services
    
    def _get_hostnames(self, scan_data: Dict[str, Any]) -> List[str]:
        """Extract hostnames from scan data"""
        hostnames = []
        for host in scan_data.get('hosts', []):
            hostnames.extend(host.get('hostnames', []))
            if host.get('address'):
                hostnames.append(host.get('address'))
        return list(set(hostnames))
    
    def _analyze_port_count(self, ports: List[int]):
        """Analyze number of open ports"""
        count = len(ports)
        self.factors['open_ports'] = count
        
        if count == 0:
            self.tci_score += 5
            self.factors['port_complexity'] = 'minimal'
        elif count <= 5:
            self.tci_score += 15
            self.factors['port_complexity'] = 'low'
        elif count <= 20:
            self.tci_score += 30
            self.factors['port_complexity'] = 'medium'
        elif count <= 50:
            self.tci_score += 50
            self.factors['port_complexity'] = 'high'
        else:
            self.tci_score += 70
            self.factors['port_complexity'] = 'very_high'
    
    def _analyze_service_types(self, services: Dict[int, str]):
        """Analyze types of services running"""
        web_services = ['http', 'https', 'nginx', 'apache', 'tomcat', 'iis', 'lighttpd']
        db_services = ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'cassandra', 'mariadb']
        auth_services = ['ldap', 'kerberos', 'radius', 'saml', 'oauth']
        admin_services = ['ssh', 'rdp', 'vnc', 'telnet', 'ftp', 'sftp', 'smb']
        mail_services = ['smtp', 'pop3', 'imap', 'exchange']
        
        score = 0
        for port, svc in services.items():
            svc_lower = svc.lower()
            
            # Web services - potential for OWASP Top 10
            if any(web in svc_lower for web in web_services):
                score += 10
                self.factors['has_web'] = True
            
            # Database services - critical data exposure
            if any(db in svc_lower for db in db_services):
                score += 15
                self.factors['has_database'] = True
            
            # Authentication services - privilege escalation risk
            if any(auth in svc_lower for auth in auth_services):
                score += 12
                self.factors['has_auth'] = True
            
            # Admin services - high risk
            if any(admin in svc_lower for admin in admin_services):
                score += 8
                self.factors['has_admin'] = True
            
            # Mail services - data leakage
            if any(mail in svc_lower for mail in mail_services):
                score += 5
                self.factors['has_mail'] = True
        
        self.tci_score += min(score, 40)
        self.factors['service_complexity'] = score
    
    def _analyze_web_services(self, services: Dict[int, str]):
        """Special analysis for web services"""
        web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000]
        web_services = ['http', 'https']
        
        web_found = False
        for port, svc in services.items():
            if port in web_ports or svc.lower() in web_services:
                web_found = True
                break
        
        if web_found:
            self.tci_score += 10
            self.factors['web_present'] = True
            self.factors['web_complexity'] = 'additional_web_scan_needed'
    
    def _analyze_auth_services(self, services: Dict[int, str]):
        """Analyze authentication complexity"""
        auth_keywords = ['auth', 'login', 'oauth', 'saml', 'ldap', 'radius', 'kerberos']
        
        auth_found = False
        for port, svc in services.items():
            svc_lower = svc.lower()
            if any(keyword in svc_lower for keyword in auth_keywords):
                auth_found = True
                break
        
        if auth_found:
            self.tci_score += 15
            self.factors['auth_complexity'] = 'authentication_present'
    
    def _analyze_hostname_complexity(self, hostnames: List[str]):
        """Analyze hostname patterns for subdomain enumeration potential"""
        if not hostnames:
            return
        
        # Check for subdomain patterns
        subdomain_pattern = r'^[a-zA-Z0-9-]+\.'
        subdomain_count = 0
        for host in hostnames:
            if re.match(subdomain_pattern, host):
                subdomain_count += 1
        
        if subdomain_count > 0:
            self.tci_score += 5
            self.factors['subdomain_present'] = subdomain_count
    
    def _get_severity_label(self) -> str:
        """Get severity label based on TCI score"""
        if self.tci_score >= 80:
            return 'critical'
        elif self.tci_score >= 60:
            return 'high'
        elif self.tci_score >= 40:
            return 'medium'
        elif self.tci_score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_plan(self):
        """Generate recommended scan plan based on TCI analysis"""
        plan = []
        factors = self.factors
        
        # Base plan - always do basic scan
        plan.append({
            'phase': 'base',
            'action': 'basic_recon',
            'description': 'Perform initial Nmap scan for port/service discovery',
            'priority': 1
        })
        
        # If web services present - add web scan
        if factors.get('web_present'):
            plan.append({
                'phase': 'web',
                'action': 'web_application_scan',
                'description': 'Comprehensive web app security scan (OWASP Top 10)',
                'priority': 2
            })
        
        # If auth services present - add auth enumeration
        if factors.get('auth_complexity'):
            plan.append({
                'phase': 'auth',
                'action': 'authentication_enumeration',
                'description': 'Identify and test authentication mechanisms',
                'priority': 3
            })
        
        # If database present - add DB scan
        if factors.get('has_database'):
            plan.append({
                'phase': 'database',
                'action': 'database_security_scan',
                'description': 'Database configuration and vulnerability assessment',
                'priority': 4
            })
        
        # If many services present - add lateral movement check
        if factors.get('service_complexity', 0) > 30:
            plan.append({
                'phase': 'advanced',
                'action': 'lateral_movement_analysis',
                'description': 'Check for privilege escalation and lateral movement paths',
                'priority': 5
            })
        
        # If subdomains present - add subdomain enumeration
        if factors.get('subdomain_present'):
            plan.append({
                'phase': 'recon',
                'action': 'subdomain_enumeration',
                'description': 'Discover and scan subdomains',
                'priority': 6
            })
        
        # Final audit
        plan.append({
            'phase': 'final',
            'action': 'audit_consolidation',
            'description': 'Consolidate findings and generate comprehensive report',
            'priority': 7
        })
        
        self.plan = plan


def get_tci_plan(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to get TCI plan from scan data.
    
    Args:
        scan_data: Nmap scan results (parsed)
        
    Returns:
        Dict with TCI analysis and recommended plan
    """
    tci = TCI()
    return tci.analyze_target(scan_data)


# Test function
def test_tci():
    """Test TCI functionality with sample data"""
    
    # Sample scan data (like from Nmap)
    sample_scan = {
        'hosts': [
            {
                'address': '192.168.1.100',
                'hostnames': ['web.example.com', 'api.example.com'],
                'ports': [
                    {'portid': 80, 'state': 'open', 'service': {'name': 'http'}},
                    {'portid': 443, 'state': 'open', 'service': {'name': 'https'}},
                    {'portid': 22, 'state': 'open', 'service': {'name': 'ssh'}},
                    {'portid': 3306, 'state': 'open', 'service': {'name': 'mysql'}},
                    {'portid': 8080, 'state': 'open', 'service': {'name': 'http-alt'}},
                ]
            }
        ]
    }
    
    result = get_tci_plan(sample_scan)
    
    print("\n" + "="*50)
    print("TCI Analysis Results")
    print("="*50)
    print(f"TCI Score: {result['tci_score']}/100")
    print(f"Severity: {result['severity'].upper()}")
    print("\nFactors:")
    for key, value in result['factors'].items():
        print(f"  - {key}: {value}")
    print("\nRecommended Scan Plan:")
    for step in result['recommended_plan']:
        print(f"  {step['priority']}. [{step['phase']}] {step['action']}")
        print(f"     {step['description']}")
    print("="*50)
    
    return result


if __name__ == "__main__":
    test_tci()
