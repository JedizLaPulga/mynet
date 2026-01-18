"""
Severity Scoring Engine for MyNet Scanner.

Provides consistent severity classification across all scanner modules,
risk scoring, and executive summary generation.

Severity Levels:
- CRITICAL (10): Immediate exploitation possible, high impact
- HIGH (8): Exploitable with specific conditions, significant impact
- MEDIUM (5): Potential security issue, moderate impact
- LOW (3): Minor security concern, low impact
- INFO (1): Informational finding, no direct security impact
"""

from typing import Dict, Any, List, Tuple
from enum import Enum
from dataclasses import dataclass, field


class Severity(Enum):
    """Severity levels with numeric scores."""
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 3
    INFO = 1
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
        }
        return mapping.get(value.lower().strip(), cls.INFO)
    
    @property
    def color(self) -> str:
        """Get rich console color for this severity."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }
        return colors.get(self, "white")
    
    @property
    def emoji(self) -> str:
        """Get emoji indicator for this severity."""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        return emojis.get(self, "")


@dataclass
class Finding:
    """Represents a single security finding."""
    module: str
    severity: Severity
    title: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def score(self) -> int:
        return self.severity.value


@dataclass
class SeveritySummary:
    """Summary of findings by severity level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    findings: List[Finding] = field(default_factory=list)
    
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info
    
    @property
    def risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        if self.total == 0:
            return 0
        
        # Weighted score calculation
        weighted = (
            self.critical * Severity.CRITICAL.value +
            self.high * Severity.HIGH.value +
            self.medium * Severity.MEDIUM.value +
            self.low * Severity.LOW.value +
            self.info * Severity.INFO.value
        )
        
        # Normalize to 0-100 scale
        # Max possible per finding is 10 (critical), so divide by total * 10 * 100
        max_score = self.total * 10
        return min(100, int((weighted / max_score) * 100)) if max_score > 0 else 0
    
    @property
    def risk_level(self) -> str:
        """Get overall risk level label."""
        if self.critical > 0:
            return "CRITICAL"
        elif self.high > 0:
            return "HIGH"
        elif self.medium > 0:
            return "MEDIUM"
        elif self.low > 0:
            return "LOW"
        elif self.info > 0:
            return "INFO"
        return "NONE"
    
    @property
    def risk_color(self) -> str:
        """Get color for overall risk level."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
            "NONE": "green",
        }
        return colors.get(self.risk_level, "white")


class SeverityScorer:
    """
    Analyzes scan results and assigns severity scores to findings.
    
    Maps module-specific results to standardized severity levels.
    """
    
    def __init__(self):
        # Module-specific severity rules
        self._init_rules()
    
    def _init_rules(self):
        """Initialize severity rules for each module type."""
        
        # CORS Scanner rules
        self.cors_rules = {
            "origin_reflection": lambda v: Severity.CRITICAL if v.get("credentials_allowed") else Severity.HIGH,
            "null_origin": lambda v: Severity.CRITICAL if v.get("credentials_allowed") else Severity.HIGH,
            "wildcard_credentials": lambda _: Severity.HIGH,
            "wildcard_origin": lambda _: Severity.INFO,
            "subdomain_trust": lambda _: Severity.MEDIUM,
            "special_origin": lambda _: Severity.MEDIUM,
            "preflight_bypass": lambda v: Severity.HIGH if v.get("dangerous_methods") else Severity.MEDIUM,
        }
        
        # Host Header Injection rules
        self.host_header_rules = {
            "reflected_in_redirect": Severity.HIGH,
            "cache_poisoning_potential": Severity.HIGH,
            "metadata_access": Severity.CRITICAL,
            "reflected_in_body": Severity.MEDIUM,
            "reflected_in_header": Severity.MEDIUM,
            "causes_redirect": Severity.MEDIUM,
            "causes_error": Severity.LOW,
            "double_host_header": Severity.HIGH,
        }
        
        # Open Redirect Scanner rules
        self.redirect_rules = {
            "direct": Severity.HIGH,
            "bypass": Severity.MEDIUM,
            "partial": Severity.LOW,
        }
        
        # HTTP Method Scanner rules
        self.method_severity = {
            "PUT": Severity.HIGH,
            "DELETE": Severity.HIGH,
            "TRACE": Severity.MEDIUM,
            "OPTIONS_VERBOSE": Severity.LOW,
            "CONNECT": Severity.MEDIUM,
        }
    
    def analyze(self, results: Dict[str, Any]) -> SeveritySummary:
        """
        Analyze full scan results and return severity summary.
        
        Args:
            results: Full scan results dictionary from Runner
            
        Returns:
            SeveritySummary with all findings categorized by severity
        """
        summary = SeveritySummary()
        
        for host, data in results.items():
            scans = data.get("scans", {})
            
            for module_name, scan_data in scans.items():
                if isinstance(scan_data, dict) and "error" not in scan_data:
                    findings = self._extract_findings(module_name, scan_data)
                    summary.findings.extend(findings)
                    
                    for finding in findings:
                        self._increment_count(summary, finding.severity)
        
        return summary
    
    def _increment_count(self, summary: SeveritySummary, severity: Severity):
        """Increment the appropriate severity count."""
        if severity == Severity.CRITICAL:
            summary.critical += 1
        elif severity == Severity.HIGH:
            summary.high += 1
        elif severity == Severity.MEDIUM:
            summary.medium += 1
        elif severity == Severity.LOW:
            summary.low += 1
        else:
            summary.info += 1
    
    def _extract_findings(self, module: str, data: Dict[str, Any]) -> List[Finding]:
        """Extract findings from a module's scan data."""
        findings = []
        
        # Route to appropriate extractor
        extractors = {
            "CORS Scanner": self._extract_cors,
            "Host Header Injection": self._extract_host_header,
            "Open Redirect Scanner": self._extract_redirects,
            "HTTP Method Scanner": self._extract_methods,
            "WAF Detection": self._extract_waf,
            "Subdomain Takeover": self._extract_takeover,
            "Zone Transfer Scanner": self._extract_axfr,
            "JS Secret Scanner": self._extract_secrets,
            "Sensitive File Fuzzer": self._extract_files,
            "Security Headers": self._extract_headers,
            "SSL Scanner": self._extract_ssl,
            "Vuln Scanner": self._extract_vulns,
            "API Scanner": self._extract_api,
            "Port Scanner": self._extract_ports,
        }
        
        extractor = extractors.get(module)
        if extractor:
            findings.extend(extractor(data))
        
        return findings
    
    def _extract_cors(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract CORS vulnerability findings."""
        findings = []
        
        if not data.get("vulnerable"):
            return findings
        
        for vuln in data.get("vulnerabilities", []):
            vuln_type = vuln.get("type", "")
            rule = self.cors_rules.get(vuln_type)
            
            if callable(rule):
                severity = rule(vuln)
            else:
                severity = Severity.from_string(vuln.get("severity", "info"))
            
            findings.append(Finding(
                module="CORS Scanner",
                severity=severity,
                title=f"CORS {vuln_type.replace('_', ' ').title()}",
                description=vuln.get("description", ""),
                details=vuln,
            ))
        
        return findings
    
    def _extract_host_header(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract Host Header Injection findings."""
        findings = []
        
        if not data.get("vulnerable"):
            return findings
        
        for vuln in data.get("vulnerabilities", []):
            vuln_type = vuln.get("type", "")
            severity = self.host_header_rules.get(vuln_type, Severity.LOW)
            
            findings.append(Finding(
                module="Host Header Injection",
                severity=severity,
                title=f"Host Header: {vuln_type.replace('_', ' ').title()}",
                description=vuln.get("description", ""),
                details=vuln,
            ))
        
        return findings
    
    def _extract_redirects(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract Open Redirect findings."""
        findings = []
        
        if not data.get("vulnerable"):
            return findings
        
        for vuln in data.get("vulnerabilities", []):
            redirect_type = vuln.get("type", "direct")
            severity = self.redirect_rules.get(redirect_type, Severity.MEDIUM)
            
            findings.append(Finding(
                module="Open Redirect Scanner",
                severity=severity,
                title=f"Open Redirect ({redirect_type})",
                description=f"Parameter: {vuln.get('parameter', 'N/A')}",
                details=vuln,
            ))
        
        return findings
    
    def _extract_methods(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract dangerous HTTP method findings."""
        findings = []
        
        for result in data.get("results", []):
            if result.get("dangerous"):
                method = result.get("method", "")
                severity = self.method_severity.get(method, Severity.MEDIUM)
                
                findings.append(Finding(
                    module="HTTP Method Scanner",
                    severity=severity,
                    title=f"Dangerous HTTP Method: {method}",
                    description=f"Status: {result.get('status')}",
                    details=result,
                ))
        
        return findings
    
    def _extract_waf(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract WAF detection findings (informational)."""
        findings = []
        
        if data.get("detected"):
            wafs = data.get("wafs", [])
            findings.append(Finding(
                module="WAF Detection",
                severity=Severity.INFO,
                title=f"WAF Detected: {', '.join(wafs)}",
                description=f"Confidence: {data.get('confidence')}%",
                details=data,
            ))
        
        return findings
    
    def _extract_takeover(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract subdomain takeover findings."""
        findings = []
        
        if data.get("vulnerable"):
            findings.append(Finding(
                module="Subdomain Takeover",
                severity=Severity.CRITICAL,
                title="Subdomain Takeover Possible",
                description=f"Provider: {data.get('provider')}, CNAME: {data.get('cname')}",
                details=data,
            ))
        
        return findings
    
    def _extract_axfr(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract Zone Transfer findings."""
        findings = []
        
        if data.get("vulnerable"):
            findings.append(Finding(
                module="Zone Transfer Scanner",
                severity=Severity.HIGH,
                title="DNS Zone Transfer Allowed",
                description=f"Leaked {len(data.get('records', []))} records",
                details=data,
            ))
        
        return findings
    
    def _extract_secrets(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract JS secret findings."""
        findings = []
        
        for secret in data.get("secrets", []):
            secret_type = secret.get("type", "")
            
            # API keys and tokens are high severity
            if any(x in secret_type.lower() for x in ["api", "key", "token", "secret", "credential"]):
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
            
            findings.append(Finding(
                module="JS Secret Scanner",
                severity=severity,
                title=f"Exposed Secret: {secret_type}",
                description=f"Found in: {secret.get('source', 'N/A')}",
                details=secret,
            ))
        
        return findings
    
    def _extract_files(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract sensitive file findings."""
        findings = []
        
        for f in data.get("found", []):
            url = f.get("url", "")
            
            # Categorize by file type
            if any(x in url.lower() for x in [".git", ".env", "wp-config", "config.php"]):
                severity = Severity.HIGH
            elif any(x in url.lower() for x in [".bak", ".backup", ".old", ".sql"]):
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            
            findings.append(Finding(
                module="Sensitive File Fuzzer",
                severity=severity,
                title=f"Sensitive File: {url.split('/')[-1]}",
                description=f"Status: {f.get('status')}, Size: {f.get('size')}",
                details=f,
            ))
        
        return findings
    
    def _extract_headers(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract security header findings."""
        findings = []
        
        score = data.get("score", 100)
        missing = data.get("missing", [])
        
        if score < 50:
            severity = Severity.MEDIUM
        elif score < 80:
            severity = Severity.LOW
        else:
            return findings  # Good score, no finding
        
        if missing:
            findings.append(Finding(
                module="Security Headers",
                severity=severity,
                title=f"Missing Security Headers ({len(missing)})",
                description=f"Security Score: {score}/100",
                details={"missing": missing, "score": score},
            ))
        
        return findings
    
    def _extract_ssl(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract SSL certificate findings."""
        findings = []
        
        # Check for expiration
        if data.get("expired"):
            findings.append(Finding(
                module="SSL Scanner",
                severity=Severity.HIGH,
                title="SSL Certificate Expired",
                description=f"Expired: {data.get('valid_to', 'N/A')}",
                details=data,
            ))
        elif data.get("expires_soon"):
            findings.append(Finding(
                module="SSL Scanner",
                severity=Severity.MEDIUM,
                title="SSL Certificate Expiring Soon",
                description=f"Expires: {data.get('valid_to', 'N/A')}",
                details=data,
            ))
        
        # Check for weak protocols/ciphers
        if data.get("weak_protocols"):
            findings.append(Finding(
                module="SSL Scanner",
                severity=Severity.MEDIUM,
                title="Weak SSL/TLS Protocols",
                description=str(data.get("weak_protocols")),
                details=data,
            ))
        
        return findings
    
    def _extract_vulns(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract CVE vulnerability findings."""
        findings = []
        
        for software, cves in data.items():
            if not isinstance(cves, list):
                continue
                
            for cve in cves:
                cvss = cve.get("cvss", 0)
                
                try:
                    score = float(cvss)
                    if score >= 9.0:
                        severity = Severity.CRITICAL
                    elif score >= 7.0:
                        severity = Severity.HIGH
                    elif score >= 4.0:
                        severity = Severity.MEDIUM
                    else:
                        severity = Severity.LOW
                except (ValueError, TypeError):
                    severity = Severity.MEDIUM
                
                findings.append(Finding(
                    module="Vuln Scanner",
                    severity=severity,
                    title=f"{cve.get('id', 'CVE')} in {software}",
                    description=cve.get("summary", "")[:100],
                    details=cve,
                ))
        
        return findings
    
    def _extract_api(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract API security findings."""
        findings = []
        
        for issue in data.get("security_issues", []):
            severity = Severity.from_string(issue.get("severity", "medium"))
            
            findings.append(Finding(
                module="API Scanner",
                severity=severity,
                title=f"API Issue: {issue.get('type', 'Unknown')}",
                description=issue.get("description", ""),
                details=issue,
            ))
        
        # GraphQL introspection enabled
        graphql = data.get("graphql", {})
        if graphql.get("found") and graphql.get("introspection_enabled"):
            findings.append(Finding(
                module="API Scanner",
                severity=Severity.MEDIUM,
                title="GraphQL Introspection Enabled",
                description="Full schema is publicly accessible",
                details=graphql,
            ))
        
        return findings
    
    def _extract_ports(self, data: Dict[str, Any]) -> List[Finding]:
        """Extract notable port findings."""
        findings = []
        
        # Define high-risk ports
        high_risk_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            27017: "MongoDB",
        }
        
        open_ports = data.get("open_ports", [])
        
        for port in open_ports:
            if port in high_risk_ports:
                findings.append(Finding(
                    module="Port Scanner",
                    severity=Severity.INFO,
                    title=f"Open Port: {port} ({high_risk_ports[port]})",
                    description="Database/Admin service exposed",
                    details={"port": port, "service": high_risk_ports[port]},
                ))
        
        return findings


def get_severity_summary(results: Dict[str, Any]) -> SeveritySummary:
    """
    Convenience function to analyze scan results.
    
    Args:
        results: Full scan results from Runner
        
    Returns:
        SeveritySummary object with categorized findings
    """
    scorer = SeverityScorer()
    return scorer.analyze(results)
