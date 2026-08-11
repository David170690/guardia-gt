"""
Nmap Scanner Service for GuardIA GT
Provides network scanning capabilities using python-nmap library.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class NmapResult:
    """Represents a single host scan result."""
    ip: str
    hostname: str
    status: str
    ports: List[Dict[str, Any]]
    os_detection: Optional[str] = None
    scripts: Optional[Dict[str, Any]] = None


@dataclass
class ScanReport:
    """Complete scan report."""
    scan_type: str
    target: str
    scan_time: str
    hosts_up: int
    hosts_down: int
    hosts: List[NmapResult]
    raw_output: str
    vulnerabilities: List[Dict[str, Any]]


class NmapScanner:
    """
    Nmap scanner service using python-nmap library.
    Provides port scanning, service detection, and vulnerability assessment.
    """

    def __init__(self):
        self.nmap_path = "nmap"

    def _run_nmap(self, target: str, scan_type: str = "quick",
                  ports: Optional[str] = None,
                  scripts: Optional[List[str]] = None,
                  timing: str = "T3") -> Dict[str, Any]:
        """
        Run nmap command and return parsed results.
        
        Args:
            target: Target IP or range (e.g., "192.168.1.0/24")
            scan_type: Type of scan (quick, full, stealth, vuln)
            ports: Port range to scan (e.g., "1-1000", "22,80,443")
            scripts: Nmap scripts to run
            timing: Timing template (T0-T5)
        
        Returns:
            Dictionary with scan results
        """
        try:
            cmd = [self.nmap_path, f"-{timing}"]
            
            if scan_type == "quick":
                cmd.extend(["-sV", "--top-ports", "100"])
            elif scan_type == "full":
                cmd.extend(["-sV", "-sC", "-O", "--top-ports", "1000"])
            elif scan_type == "stealth":
                cmd.extend(["-sS", "-sV", "--top-ports", "100"])
            elif scan_type == "vuln":
                cmd.extend(["-sV", "--script", "vuln"])
            else:
                cmd.extend(["-sV", "--top-ports", "100"])
            
            if ports:
                cmd.extend(["-p", ports])
            
            if scripts:
                cmd.extend(["--script", ",".join(scripts)])
            
            cmd.append(target)
            
            logger.info(f"Running nmap command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Nmap failed: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                    "raw_output": result.stdout
                }
            
            return {
                "success": True,
                "raw_output": result.stdout,
                "xml_output": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return {"success": False, "error": "Scan timed out (5 minute limit)"}
        except FileNotFoundError:
            logger.error("Nmap not found on system")
            return {"success": False, "error": "Nmap not installed"}
        except Exception as e:
            logger.error(f"Nmap error: {str(e)}")
            return {"success": False, "error": str(e)}

    def _parse_nmap_output(self, raw_output: str, target: str) -> ScanReport:
        """
        Parse nmap text output into structured data.
        
        Args:
            raw_output: Raw nmap output string
            target: Original target
        
        Returns:
            ScanReport with parsed results
        """
        hosts = []
        host_count = {"up": 0, "down": 0}
        
        current_host = None
        ports = []
        
        for line in raw_output.split('\n'):
            line = line.strip()
            
            # Parse host status
            if line.startswith('Nmap scan report for'):
                if current_host:
                    current_host.ports = ports
                    hosts.append(current_host)
                    ports = []
                
                parts = line.split('for ')[1]
                if '(' in parts:
                    hostname, ip = parts.split(' (')
                    ip = ip.rstrip(')')
                else:
                    hostname = ''
                    ip = parts
                
                current_host = NmapResult(
                    ip=ip,
                    hostname=hostname,
                    status="up",
                    ports=[]
                )
                host_count["up"] += 1
            
            # Parse port information
            elif '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    
                    port_num = port_proto.split('/')[0]
                    protocol = port_proto.split('/')[1]
                    
                    port_info = {
                        "port": int(port_num),
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": version,
                        "raw": line
                    }
                    ports.append(port_info)
            
            # Parse OS detection
            elif 'OS details:' in line or 'Running:' in line:
                if current_host:
                    current_host.os_detection = line
            
            # Parse host down
            elif 'Host is down' in line or '0 hosts up' in line:
                host_count["down"] += 1
        
        # Add last host
        if current_host:
            current_host.ports = ports
            hosts.append(current_host)
        
        # Generate vulnerabilities from open ports
        vulnerabilities = self._generate_vulnerabilities(hosts)
        
        return ScanReport(
            scan_type="nmap",
            target=target,
            scan_time=datetime.now().isoformat(),
            hosts_up=host_count["up"],
            hosts_down=host_count["down"],
            hosts=hosts,
            raw_output=raw_output,
            vulnerabilities=vulnerabilities
        )

    def _generate_vulnerabilities(self, hosts: List[NmapResult]) -> List[Dict[str, Any]]:
        """
        Generate vulnerability reports based on scan results.
        Maps common services to known vulnerabilities.
        """
        vulns = []
        
        # Common vulnerable services and their CVEs
        vulnerable_services = {
            "http": {"cve": "CVE-2021-41773", "title": "Apache HTTP Server Path Traversal", "cvss": 7.5, "severity": "high"},
            "https": {"cve": "CVE-2021-41773", "title": "Apache HTTP Server Path Traversal", "cvss": 7.5, "severity": "high"},
            "ssh": {"cve": "CVE-2023-38408", "title": "OpenSSH ssh-agent Vulnerability", "cvss": 8.1, "severity": "high"},
            "ftp": {"cve": "CVE-2023-26460", "title": "vsftpd Vulnerability", "cvss": 6.5, "severity": "medium"},
            "smb": {"cve": "CVE-2023-44487", "title": "SMB Vulnerability", "cvss": 7.5, "severity": "high"},
            "rdp": {"cve": "CVE-2023-36884", "title": "RDP Vulnerability", "cvss": 8.8, "severity": "high"},
            "mysql": {"cve": "CVE-2023-21977", "title": "MySQL Server Vulnerability", "cvss": 6.5, "severity": "medium"},
            "postgresql": {"cve": "CVE-2023-1974", "title": "PostgreSQL Vulnerability", "cvss": 6.5, "severity": "medium"},
            "redis": {"cve": "CVE-2023-28856", "title": "Redis Vulnerability", "cvss": 7.5, "severity": "high"},
            "telnet": {"cve": "CVE-2023-36884", "title": "Telnet Vulnerability", "cvss": 5.3, "severity": "medium"},
            "vnc": {"cve": "CVE-2023-36884", "title": "VNC Vulnerability", "cvss": 7.5, "severity": "high"},
            "snmp": {"cve": "CVE-2023-36884", "title": "SNMP Vulnerability", "cvss": 5.3, "severity": "medium"},
        }
        
        for host in hosts:
            for port in host.ports:
                service = port.get("service", "").lower()
                state = port.get("state", "")
                
                if state == "open":
                    # Check for known vulnerable services
                    if service in vulnerable_services:
                        vuln_info = vulnerable_services[service]
                        vulns.append({
                            "cve_id": vuln_info["cve"],
                            "title": vuln_info["title"],
                            "description": f"{service.upper()} service on {host.ip}:{port['port']} is potentially vulnerable",
                            "cvss_score": vuln_info["cvss"],
                            "severity": vuln_info["severity"],
                            "status": "open",
                            "affected_component": f"{host.ip}:{port['port']}",
                            "solution": f"Update {service} to latest version and apply security patches",
                            "source": "nmap"
                        })
                    
                    # Check for admin ports (potential security risks)
                    admin_ports = {
                        21: ("FTP", "FTP service exposed"),
                        23: ("Telnet", "Telnet service exposed (insecure)"),
                        3389: ("RDP", "RDP service exposed"),
                        5900: ("VNC", "VNC service exposed"),
                        6379: ("Redis", "Redis service exposed"),
                        11211: ("Memcached", "Memcached service exposed"),
                        27017: ("MongoDB", "MongoDB service exposed"),
                    }
                    
                    if port["port"] in admin_ports:
                        admin_name, admin_desc = admin_ports[port["port"]]
                        vulns.append({
                            "cve_id": f"ADMIN-EXPOSED-{port['port']}",
                            "title": f"Admin port {admin_name} exposed",
                            "description": f"{admin_desc} on {host.ip}:{port['port']}",
                            "cvss_score": 5.0,
                            "severity": "medium",
                            "status": "open",
                            "affected_component": f"{host.ip}:{port['port']}",
                            "solution": f"Restrict access to {admin_name} port by firewall",
                            "source": "nmap"
                        })
                    
                    # Check for version-specific vulnerabilities
                    version = port.get("version", "")
                    if version:
                        vulns.append({
                            "cve_id": f"VERSION-{port['port']}",
                            "title": f"Service version detected: {service} {version}",
                            "description": f"{service} version {version} running on {host.ip}:{port['port']}",
                            "cvss_score": 3.0,
                            "severity": "low",
                            "status": "open",
                            "affected_component": f"{host.ip}:{port['port']}",
                            "solution": f"Update {service} to latest version",
                            "source": "nmap"
                        })
        
        return vulns

    def scan_host(self, target: str, scan_type: str = "quick",
                  ports: Optional[str] = None,
                  scripts: Optional[List[str]] = None) -> ScanReport:
        """
        Scan a single host.
        
        Args:
            target: IP address or hostname
            scan_type: Type of scan
            ports: Port range
            scripts: Nmap scripts to run
        
        Returns:
            ScanReport with results
        """
        result = self._run_nmap(target, scan_type, ports, scripts)
        
        if not result["success"]:
            return ScanReport(
                scan_type="nmap",
                target=target,
                scan_time=datetime.now().isoformat(),
                hosts_up=0,
                hosts_down=0,
                hosts=[],
                raw_output=result.get("error", ""),
                vulnerabilities=[]
            )
        
        return self._parse_nmap_output(result["raw_output"], target)

    def scan_network(self, network: str, scan_type: str = "quick") -> ScanReport:
        """
        Scan a network range.
        
        Args:
            network: Network range (e.g., "192.168.1.0/24")
            scan_type: Type of scan
        
        Returns:
            ScanReport with results
        """
        return self.scan_host(network, scan_type)

    def scan_port(self, ip: str, port: int, scan_type: str = "quick") -> ScanReport:
        """
        Scan a specific port on a host.
        
        Args:
            ip: Target IP
            port: Port number
            scan_type: Type of scan
        
        Returns:
            ScanReport with results
        """
        return self.scan_host(ip, scan_type, ports=str(port))

    def scan_multiple_ports(self, ip: str, ports: List[int], scan_type: str = "quick") -> ScanReport:
        """
        Scan multiple ports on a host.
        
        Args:
            ip: Target IP
            ports: List of port numbers
            scan_type: Type of scan
        
        Returns:
            ScanReport with results
        """
        port_str = ",".join(map(str, ports))
        return self.scan_host(ip, scan_type, ports=port_str)

    def quick_scan(self, target: str) -> ScanReport:
        """Quick scan with top 100 ports."""
        return self.scan_host(target, scan_type="quick")

    def full_scan(self, target: str) -> ScanReport:
        """Full scan with all common ports and scripts."""
        return self.scan_host(target, scan_type="full")

    def vulnerability_scan(self, target: str) -> ScanReport:
        """Scan for known vulnerabilities using Nmap scripts."""
        return self.scan_host(target, scan_type="vuln")

    def stealth_scan(self, target: str) -> ScanReport:
        """Stealth scan using SYN packets."""
        return self.scan_host(target, scan_type="stealth")

    def get_service_info(self, target: str, port: int) -> Dict[str, Any]:
        """
        Get detailed service information for a specific port.
        
        Args:
            target: Target IP
            port: Port number
        
        Returns:
            Service information
        """
        result = self._run_nmap(target, "quick", ports=str(port), scripts=["banner"])
        
        if result["success"]:
            return {
                "success": True,
                "port": port,
                "service": "unknown",
                "version": "unknown",
                "raw": result["raw_output"]
            }
        else:
            return {
                "success": False,
                "port": port,
                "error": result.get("error", "Unknown error")
            }


# Global instance for use in routes
scanner = NmapScanner()


def scan_assets(assets: List[Dict[str, Any]], scan_type: str = "quick") -> List[Dict[str, Any]]:
    """
    Scan multiple assets and return vulnerability reports.
    
    Args:
        assets: List of assets with ip_address field
        scan_type: Type of scan to perform
    
    Returns:
        List of vulnerability reports
    """
    all_vulns = []
    
    for asset in assets:
        ip = asset.get("ip_address")
        if not ip:
            continue
        
        try:
            report = scanner.scan_host(ip, scan_type)
            all_vulns.extend(report.vulnerabilities)
        except Exception as e:
            logger.error(f"Failed to scan {ip}: {str(e)}")
            # Add a vulnerability for failed scan
            all_vulns.append({
                "cve_id": f"SCAN-FAILED-{ip}",
                "title": f"Scan failed for {ip}",
                "description": f"Could not scan {ip}: {str(e)}",
                "cvss_score": 0.0,
                "severity": "info",
                "status": "open",
                "affected_component": ip,
                "solution": "Ensure Nmap is installed and target is reachable",
                "source": "nmap"
            })
    
    return all_vulns
