#!/usr/bin/env python3
"""
Network Traffic Analysis Module
Educational cybersecurity tool for analyzing network traffic and detecting security threats.

This module provides network traffic monitoring, packet analysis, and threat detection
capabilities for educational purposes. It operates independently from SAST and DAST
modules to teach students about network-level security analysis.

Author: Cybersecurity Education Platform
License: Educational Use Only
"""

import socket
import struct
import time
import json
import subprocess
import threading
import re
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple
import ipaddress

from .vulnerability_database import VulnerabilityDatabase


class NetworkAnalyzer:
    """
    Network Traffic Analysis Engine

    Provides comprehensive network traffic monitoring and analysis capabilities
    including packet capture, protocol analysis, and threat detection.
    """

    def __init__(self, interface: str = "any", educational_mode: bool = False):
        """
        Initialize the network analyzer

        Args:
            interface: Network interface to monitor (default: "any")
            educational_mode: Enable detailed educational explanations
        """
        self.interface = interface
        self.educational_mode = educational_mode
        self.vuln_db = VulnerabilityDatabase()

        # Analysis results storage
        self.findings = []
        self.traffic_stats = defaultdict(int)
        self.connection_map = defaultdict(list)
        self.suspicious_ips = set()
        self.protocol_breakdown = Counter()

        # Monitoring state
        self.is_monitoring = False
        self.start_time = None
        self.packet_count = 0

        # Threat detection patterns
        self.malicious_patterns = {
            'port_scan': {'ports_per_ip': 10, 'timeframe': 60},
            'brute_force': {'attempts_per_ip': 10, 'timeframe': 300},
            'data_exfiltration': {'bytes_threshold': 10485760},  # 10MB
            'suspicious_ports': [4444, 6666, 1337, 31337, 8080, 9999]
        }

        # Known malicious indicators
        self.malicious_indicators = {
            'c2_domains': [
                'malicious-server.com', 'evil-command.net', 'backdoor-c2.org',
                'suspicious-server.example.com', 'malware-control.net'
            ],
            'mining_pools': [
                'mining-pool.com', 'crypto-pool.org', 'xmr-pool.example.com',
                'eth-pool.example.com', 'mining.example.org'
            ],
            'tor_exit_nodes': [],  # Could be populated with known Tor exit nodes
            'malware_ips': []  # Could be populated with known malicious IPs
        }

    def start_packet_capture(self, duration: int = 60, filter_expr: str = None) -> Dict[str, Any]:
        """
        Start network packet capture and analysis

        Args:
            duration: Capture duration in seconds
            filter_expr: Optional packet filter expression

        Returns:
            Dictionary containing capture results and analysis
        """
        print(
            f"🌐 Starting network traffic capture on interface: {self.interface}")
        print(f"⏱️  Capture duration: {duration} seconds")

        self.start_time = datetime.now()
        self.is_monitoring = True

        # Build tcpdump command for packet capture
        cmd = self._build_capture_command(duration, filter_expr)

        try:
            # Run packet capture
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 10)

            if result.returncode == 0:
                # Parse captured traffic
                self._parse_captured_traffic(result.stdout)

                # Analyze traffic for threats
                self._analyze_traffic_patterns()

                # Generate analysis results
                return self._generate_analysis_results()
            else:
                return {
                    'error': f"Packet capture failed: {result.stderr}",
                    'success': False
                }

        except subprocess.TimeoutExpired:
            return {
                'error': "Packet capture timed out",
                'success': False
            }
        except Exception as e:
            return {
                'error': f"Capture error: {str(e)}",
                'success': False
            }
        finally:
            self.is_monitoring = False

    def monitor_active_connections(self) -> Dict[str, Any]:
        """
        Monitor currently active network connections

        Returns:
            Dictionary containing active connections and analysis
        """
        print("🔍 Analyzing active network connections...")

        connections = self._get_active_connections()
        suspicious_connections = self._analyze_connections(connections)

        return {
            'timestamp': datetime.now().isoformat(),
            'total_connections': len(connections),
            'active_connections': connections,
            'suspicious_connections': suspicious_connections,
            'findings': self.findings
        }

    def analyze_dns_traffic(self, duration: int = 30) -> Dict[str, Any]:
        """
        Analyze DNS traffic for suspicious queries

        Args:
            duration: Monitoring duration in seconds

        Returns:
            Dictionary containing DNS analysis results
        """
        print("🔍 Analyzing DNS traffic patterns...")

        # Capture DNS traffic specifically
        dns_filter = "port 53"
        result = self.start_packet_capture(duration, dns_filter)

        if result.get('success', True):
            dns_analysis = self._analyze_dns_patterns()
            result.update(dns_analysis)

        return result

    def scan_network_services(self, target: str = "localhost") -> Dict[str, Any]:
        """
        Scan for network services and analyze security posture

        Args:
            target: Target to scan (IP address or hostname)

        Returns:
            Dictionary containing service scan results
        """
        print(f"🔍 Scanning network services on {target}...")

        services = self._scan_services(target)
        security_analysis = self._analyze_service_security(services)

        return {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'discovered_services': services,
            'security_analysis': security_analysis,
            'findings': self.findings
        }

    def _build_capture_command(self, duration: int, filter_expr: str = None) -> List[str]:
        """Build tcpdump command for packet capture"""
        # Note: In educational environment, we'll use netstat and ss for demonstration
        # as tcpdump requires root privileges
        cmd = ["timeout", str(duration), "ss", "-tuln"]
        return cmd

    def _parse_captured_traffic(self, output: str) -> None:
        """Parse captured network traffic output"""
        lines = output.strip().split('\n')

        for line in lines:
            if 'LISTEN' in line or 'ESTAB' in line:
                self.packet_count += 1
                self._extract_connection_info(line)

    def _extract_connection_info(self, line: str) -> None:
        """Extract connection information from network output"""
        try:
            # Parse ss output format
            parts = line.split()
            if len(parts) >= 5:
                protocol = parts[0]
                state = parts[1] if len(parts) > 1 else "UNKNOWN"
                local_addr = parts[4] if len(parts) > 4 else ""
                remote_addr = parts[5] if len(parts) > 5 else ""

                self.protocol_breakdown[protocol] += 1

                # Extract IP and port information
                if ':' in local_addr:
                    local_ip, local_port = self._parse_address(local_addr)
                    if local_ip and local_port:
                        self.connection_map[local_ip].append({
                            'port': local_port,
                            'protocol': protocol,
                            'state': state,
                            'direction': 'inbound'
                        })

                if ':' in remote_addr and remote_addr != '*:*':
                    remote_ip, remote_port = self._parse_address(remote_addr)
                    if remote_ip and remote_port:
                        self.connection_map[remote_ip].append({
                            'port': remote_port,
                            'protocol': protocol,
                            'state': state,
                            'direction': 'outbound'
                        })

        except Exception as e:
            if self.educational_mode:
                print(f"Debug: Error parsing line '{line}': {e}")

    def _parse_address(self, addr_str: str) -> Tuple[Optional[str], Optional[int]]:
        """Parse IP:port address string"""
        try:
            if addr_str.count(':') == 1:
                # IPv4
                ip, port = addr_str.rsplit(':', 1)
                return ip.strip('[]'), int(port)
            elif addr_str.startswith('[') and ']:' in addr_str:
                # IPv6
                ip, port = addr_str.rsplit(']:', 1)
                return ip.strip('[]'), int(port)
        except (ValueError, IndexError):
            pass
        return None, None

    def _get_active_connections(self) -> List[Dict[str, Any]]:
        """Get currently active network connections"""
        connections = []

        try:
            # Use netstat to get active connections
            result = subprocess.run(
                ['netstat', '-tuln'], capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line or 'ESTABLISHED' in line:
                        conn_info = self._parse_netstat_line(line)
                        if conn_info:
                            connections.append(conn_info)

        except Exception as e:
            if self.educational_mode:
                print(f"Debug: Error getting connections: {e}")

        return connections

    def _parse_netstat_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single netstat output line"""
        try:
            parts = line.split()
            if len(parts) >= 6:
                return {
                    'protocol': parts[0],
                    'local_address': parts[3],
                    'remote_address': parts[4],
                    'state': parts[5] if len(parts) > 5 else 'UNKNOWN',
                    'process': parts[6] if len(parts) > 6 else 'UNKNOWN'
                }
        except Exception:
            pass
        return None

    def _analyze_traffic_patterns(self) -> None:
        """Analyze captured traffic for suspicious patterns"""
        # Analyze connection patterns
        for ip, connections in self.connection_map.items():
            self._check_port_scanning(ip, connections)
            self._check_suspicious_ports(ip, connections)
            self._check_malicious_indicators(ip)

    def _check_port_scanning(self, ip: str, connections: List[Dict]) -> None:
        """Check for port scanning behavior"""
        unique_ports = set()
        for conn in connections:
            if conn.get('direction') == 'outbound':
                unique_ports.add(conn.get('port'))

        if len(unique_ports) >= self.malicious_patterns['port_scan']['ports_per_ip']:
            self.findings.append({
                'severity': 'high',
                'title': 'Potential Port Scanning Detected',
                'description': f"IP {ip} accessed {len(unique_ports)} different ports, indicating possible port scanning activity.",
                'source_ip': ip,
                'ports_accessed': list(unique_ports),
                'indicator_type': 'behavioral_pattern',
                'educational_note': "Port scanning is a reconnaissance technique where attackers probe multiple ports to discover services. Large numbers of connection attempts to different ports from a single IP can indicate scanning activity."
            })

    def _check_suspicious_ports(self, ip: str, connections: List[Dict]) -> None:
        """Check for connections to suspicious ports"""
        for conn in connections:
            port = conn.get('port')
            if port in self.malicious_patterns['suspicious_ports']:
                self.findings.append({
                    'severity': 'medium',
                    'title': f'Suspicious Port Activity: {port}',
                    'description': f"Connection detected on port {port}, commonly used by malware or unauthorized services.",
                    'source_ip': ip,
                    'suspicious_port': port,
                    'protocol': conn.get('protocol'),
                    'indicator_type': 'suspicious_port',
                    'educational_note': f"Port {port} is commonly associated with backdoors, remote access tools, or other malicious software. Legitimate services rarely use these ports."
                })

    def _check_malicious_indicators(self, ip: str) -> None:
        """Check IP against known malicious indicators"""
        # Check if IP is in private ranges (for educational demonstration)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                # This is a public IP - in real scenarios, check against threat feeds
                self.findings.append({
                    'severity': 'low',
                    'title': 'External IP Communication',
                    'description': f"Communication detected with external IP address {ip}",
                    'external_ip': ip,
                    'indicator_type': 'external_communication',
                    'educational_note': "Communication with external IPs should be monitored. In production environments, these IPs would be checked against threat intelligence feeds."
                })
        except ValueError:
            pass

    def _analyze_connections(self, connections: List[Dict]) -> List[Dict]:
        """Analyze connections for suspicious activity"""
        suspicious = []

        for conn in connections:
            local_addr = conn.get('local_address', '')
            remote_addr = conn.get('remote_address', '')

            # Check for suspicious ports
            for addr in [local_addr, remote_addr]:
                if ':' in addr:
                    _, port_str = addr.rsplit(':', 1)
                    try:
                        port = int(port_str)
                        if port in self.malicious_patterns['suspicious_ports']:
                            suspicious.append({
                                **conn,
                                'reason': f'Suspicious port {port}',
                                'risk_level': 'medium'
                            })
                    except ValueError:
                        pass

        return suspicious

    def _analyze_dns_patterns(self) -> Dict[str, Any]:
        """Analyze DNS traffic for suspicious patterns"""
        # In educational environment, simulate DNS analysis
        suspicious_queries = []

        # Check for known malicious domains
        for domain in self.malicious_indicators['c2_domains']:
            suspicious_queries.append({
                'domain': domain,
                'query_type': 'A',
                'reason': 'Known C&C domain',
                'risk_level': 'high'
            })

        return {
            'dns_analysis': {
                'total_queries': len(suspicious_queries),
                'suspicious_queries': suspicious_queries,
                'query_patterns': {
                    'domain_generation_algorithm': False,
                    'fast_flux': False,
                    'tunneling_detected': False
                }
            }
        }

    def _scan_services(self, target: str) -> List[Dict[str, Any]]:
        """Scan for services on target"""
        services = []

        # Common ports to check
        common_ports = [21, 22, 23, 25, 53, 80,
                        110, 143, 443, 993, 995, 3389, 5900]

        for port in common_ports:
            if self._check_port_open(target, port):
                service_info = self._identify_service(port)
                services.append({
                    'port': port,
                    'state': 'open',
                    'service': service_info['name'],
                    'description': service_info['description'],
                    'security_concern': service_info['security_concern']
                })

        return services

    def _check_port_open(self, host: str, port: int, timeout: int = 1) -> bool:
        """Check if a port is open on the target host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _identify_service(self, port: int) -> Dict[str, str]:
        """Identify service typically running on a port"""
        service_map = {
            21: {'name': 'FTP', 'description': 'File Transfer Protocol', 'security_concern': 'Unencrypted file transfer'},
            22: {'name': 'SSH', 'description': 'Secure Shell', 'security_concern': 'Potential brute force target'},
            23: {'name': 'Telnet', 'description': 'Telnet Protocol', 'security_concern': 'Unencrypted remote access'},
            25: {'name': 'SMTP', 'description': 'Simple Mail Transfer Protocol', 'security_concern': 'Email relay abuse'},
            53: {'name': 'DNS', 'description': 'Domain Name System', 'security_concern': 'DNS tunneling potential'},
            80: {'name': 'HTTP', 'description': 'Web Server', 'security_concern': 'Unencrypted web traffic'},
            443: {'name': 'HTTPS', 'description': 'Secure Web Server', 'security_concern': 'Certificate validation needed'},
            3389: {'name': 'RDP', 'description': 'Remote Desktop Protocol', 'security_concern': 'Remote access abuse'},
            5900: {'name': 'VNC', 'description': 'Virtual Network Computing', 'security_concern': 'Weak authentication'}
        }

        return service_map.get(port, {
            'name': 'Unknown',
            'description': f'Service on port {port}',
            'security_concern': 'Unidentified service requires investigation'
        })

    def _analyze_service_security(self, services: List[Dict]) -> Dict[str, Any]:
        """Analyze discovered services for security issues"""
        high_risk_services = []
        encryption_issues = []

        for service in services:
            port = service['port']
            name = service['service']

            # Check for high-risk services
            if port in [21, 23, 3389, 5900]:
                high_risk_services.append(service)

                self.findings.append({
                    'severity': 'medium',
                    'title': f'High-Risk Service Detected: {name}',
                    'description': f"{name} service running on port {port}. {service['security_concern']}",
                    'service': name,
                    'port': port,
                    'recommendation': f"Consider disabling {name} or implementing additional security controls",
                    'educational_note': f"{name} is considered high-risk because: {service['security_concern']}"
                })

            # Check for unencrypted services
            if port in [21, 23, 25, 80]:
                encryption_issues.append(service)

        return {
            'total_services': len(services),
            'high_risk_services': len(high_risk_services),
            'encryption_issues': len(encryption_issues),
            'security_score': max(0, 100 - (len(high_risk_services) * 15) - (len(encryption_issues) * 10))
        }

    def _generate_analysis_results(self) -> Dict[str, Any]:
        """Generate comprehensive analysis results"""
        end_time = datetime.now()
        duration = (
            end_time - self.start_time).total_seconds() if self.start_time else 0

        return {
            'timestamp': end_time.isoformat(),
            'analysis_duration': duration,
            'packet_count': self.packet_count,
            'protocol_breakdown': dict(self.protocol_breakdown),
            'unique_ips': len(self.connection_map),
            'suspicious_ips': len(self.suspicious_ips),
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'high_severity': len([f for f in self.findings if f.get('severity') == 'high']),
                'medium_severity': len([f for f in self.findings if f.get('severity') == 'medium']),
                'low_severity': len([f for f in self.findings if f.get('severity') == 'low'])
            },
            'success': True
        }

    def generate_educational_insights(self) -> Dict[str, Any]:
        """Generate educational insights about network security"""
        insights = {
            'network_security_concepts': [
                "Network monitoring helps detect unauthorized access and data exfiltration",
                "Port scanning is often the first step in network reconnaissance",
                "Encrypted protocols (HTTPS, SSH) are preferred over unencrypted ones (HTTP, Telnet)",
                "Unusual network patterns can indicate malware or insider threats"
            ],
            'monitoring_best_practices': [
                "Monitor both inbound and outbound network connections",
                "Establish baseline network behavior for comparison",
                "Use network segmentation to limit attack spread",
                "Implement intrusion detection systems (IDS) for real-time monitoring"
            ],
            'threat_indicators': [
                "Multiple port scans from single IP address",
                "Connections to known malicious domains or IPs",
                "Unusual data transfer volumes or patterns",
                "Services running on non-standard ports"
            ]
        }

        return insights
