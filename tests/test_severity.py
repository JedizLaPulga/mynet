"""
Tests for the severity scoring module.
"""

import pytest
from mynet.core.severity import (
    Severity,
    Finding,
    SeveritySummary,
    SeverityScorer,
    get_severity_summary,
)


class TestSeverityEnum:
    """Test Severity enum functionality."""
    
    def test_severity_values(self):
        """Test severity numeric values."""
        assert Severity.CRITICAL.value == 10
        assert Severity.HIGH.value == 8
        assert Severity.MEDIUM.value == 5
        assert Severity.LOW.value == 3
        assert Severity.INFO.value == 1
    
    def test_from_string(self):
        """Test string to severity conversion."""
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM
        assert Severity.from_string("low") == Severity.LOW
        assert Severity.from_string("info") == Severity.INFO
        assert Severity.from_string("informational") == Severity.INFO
        assert Severity.from_string("unknown") == Severity.INFO
    
    def test_color_property(self):
        """Test severity color mapping."""
        assert Severity.CRITICAL.color == "bold red"
        assert Severity.HIGH.color == "red"
        assert Severity.MEDIUM.color == "yellow"
        assert Severity.LOW.color == "cyan"
        assert Severity.INFO.color == "dim"
    
    def test_emoji_property(self):
        """Test severity emoji mapping."""
        assert Severity.CRITICAL.emoji == "🔴"
        assert Severity.HIGH.emoji == "🟠"
        assert Severity.MEDIUM.emoji == "🟡"
        assert Severity.LOW.emoji == "🔵"
        assert Severity.INFO.emoji == "⚪"


class TestFinding:
    """Test Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a Finding."""
        finding = Finding(
            module="CORS Scanner",
            severity=Severity.CRITICAL,
            title="CORS Origin Reflection",
            description="Server reflects arbitrary origins with credentials",
        )
        
        assert finding.module == "CORS Scanner"
        assert finding.severity == Severity.CRITICAL
        assert finding.title == "CORS Origin Reflection"
        assert finding.score == 10
    
    def test_finding_with_details(self):
        """Test Finding with extra details."""
        finding = Finding(
            module="Test",
            severity=Severity.HIGH,
            title="Test Finding",
            description="Test",
            details={"key": "value", "port": 443},
        )
        
        assert finding.details["key"] == "value"
        assert finding.details["port"] == 443


class TestSeveritySummary:
    """Test SeveritySummary dataclass."""
    
    def test_empty_summary(self):
        """Test empty summary defaults."""
        summary = SeveritySummary()
        
        assert summary.total == 0
        assert summary.risk_score == 0
        assert summary.risk_level == "NONE"
        assert summary.risk_color == "green"
    
    def test_total_calculation(self):
        """Test total findings calculation."""
        summary = SeveritySummary(
            critical=2,
            high=3,
            medium=5,
            low=4,
            info=10,
        )
        
        assert summary.total == 24
    
    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        # All critical findings
        summary = SeveritySummary(critical=5)
        assert summary.risk_score == 100
        
        # All info findings
        summary = SeveritySummary(info=5)
        assert summary.risk_score == 10  # 5 * 1 / 50 * 100 = 10%
        
        # Mixed findings
        summary = SeveritySummary(critical=1, high=2, medium=3)
        # (10 + 16 + 15) / (6 * 10) * 100 = 68.3%
        assert 65 <= summary.risk_score <= 70
    
    def test_risk_level(self):
        """Test risk level determination."""
        assert SeveritySummary(critical=1).risk_level == "CRITICAL"
        assert SeveritySummary(high=1).risk_level == "HIGH"
        assert SeveritySummary(medium=1).risk_level == "MEDIUM"
        assert SeveritySummary(low=1).risk_level == "LOW"
        assert SeveritySummary(info=1).risk_level == "INFO"
        assert SeveritySummary().risk_level == "NONE"
        
        # Critical takes precedence
        assert SeveritySummary(critical=1, high=5, medium=10).risk_level == "CRITICAL"


class TestSeverityScorer:
    """Test SeverityScorer analysis."""
    
    def test_empty_results(self):
        """Test scoring empty results."""
        scorer = SeverityScorer()
        summary = scorer.analyze({})
        
        assert summary.total == 0
        assert len(summary.findings) == 0
    
    def test_cors_critical_finding(self):
        """Test CORS vulnerability with credentials marked as critical."""
        results = {
            "example.com": {
                "target": {"type": "domain"},
                "scans": {
                    "CORS Scanner": {
                        "vulnerable": True,
                        "vulnerabilities": [
                            {
                                "type": "origin_reflection",
                                "credentials_allowed": True,
                                "description": "Server reflects evil.com with credentials",
                                "severity": "critical",
                            }
                        ],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.critical == 1
        assert summary.total == 1
        assert len(summary.findings) == 1
        assert summary.findings[0].severity == Severity.CRITICAL
    
    def test_cors_high_without_credentials(self):
        """Test CORS vulnerability without credentials marked as high."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "CORS Scanner": {
                        "vulnerable": True,
                        "vulnerabilities": [
                            {
                                "type": "origin_reflection",
                                "credentials_allowed": False,
                                "description": "Server reflects evil.com",
                            }
                        ],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.high == 1
        assert summary.findings[0].severity == Severity.HIGH
    
    def test_host_header_severity_mapping(self):
        """Test Host Header vulnerability severity mapping."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "Host Header Injection": {
                        "vulnerable": True,
                        "vulnerabilities": [
                            {"type": "metadata_access", "description": "AWS metadata"},
                            {"type": "cache_poisoning_potential", "description": "Cache"},
                            {"type": "reflected_in_body", "description": "Reflected"},
                        ],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.critical == 1  # metadata_access
        assert summary.high == 1  # cache_poisoning_potential
        assert summary.medium == 1  # reflected_in_body
        assert summary.total == 3
    
    def test_subdomain_takeover_critical(self):
        """Test subdomain takeover is marked critical."""
        results = {
            "sub.example.com": {
                "target": {},
                "scans": {
                    "Subdomain Takeover": {
                        "vulnerable": True,
                        "provider": "AWS S3",
                        "cname": "bucket.s3.amazonaws.com",
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.critical == 1
        assert "Subdomain Takeover" in summary.findings[0].title
    
    def test_zone_transfer_high(self):
        """Test zone transfer is marked high."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "Zone Transfer Scanner": {
                        "vulnerable": True,
                        "records": ["record1", "record2", "record3"],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.high == 1
    
    def test_js_secrets_severity(self):
        """Test JS secrets get appropriate severity."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "JS Secret Scanner": {
                        "secrets": [
                            {"type": "API_KEY", "value": "xxx", "source": "app.js"},
                            {"type": "Generic Secret", "value": "yyy", "source": "main.js"},
                            {"type": "URL", "value": "http://example.com", "source": "config.js"},
                        ],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.high == 2  # API_KEY and Generic Secret
        assert summary.medium == 1  # URL
    
    def test_vuln_scanner_cvss_mapping(self):
        """Test CVE severity based on CVSS score."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "Vuln Scanner": {
                        "Apache 2.4.49": [
                            {"id": "CVE-2021-41773", "cvss": "9.8", "summary": "Path traversal"},
                            {"id": "CVE-2021-00000", "cvss": "7.5", "summary": "RCE"},
                            {"id": "CVE-2021-00001", "cvss": "4.3", "summary": "XSS"},
                            {"id": "CVE-2021-00002", "cvss": "2.0", "summary": "Info"},
                        ],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.critical == 1  # CVSS >= 9.0
        assert summary.high == 1  # CVSS >= 7.0
        assert summary.medium == 1  # CVSS >= 4.0
        assert summary.low == 1  # CVSS < 4.0
    
    def test_waf_detection_info(self):
        """Test WAF detection is informational."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "WAF Detection": {
                        "detected": True,
                        "wafs": ["Cloudflare", "AWS WAF"],
                        "confidence": 85,
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.info == 1
        assert summary.findings[0].severity == Severity.INFO
    
    def test_sensitive_files_severity(self):
        """Test sensitive file severity classification."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "Sensitive File Fuzzer": {
                        "found": [
                            {"url": "http://example.com/.git/config", "status": 200, "size": 100},
                            {"url": "http://example.com/.env", "status": 200, "size": 50},
                            {"url": "http://example.com/backup.sql.bak", "status": 200, "size": 1000},
                            {"url": "http://example.com/readme.txt", "status": 200, "size": 200},
                        ],
                    }
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.high == 2  # .git and .env
        assert summary.medium == 1  # .bak
        assert summary.low == 1  # readme.txt
    
    def test_multiple_hosts(self):
        """Test scoring across multiple hosts."""
        results = {
            "host1.com": {
                "target": {},
                "scans": {
                    "Subdomain Takeover": {"vulnerable": True, "provider": "S3", "cname": "x"},
                },
            },
            "host2.com": {
                "target": {},
                "scans": {
                    "Zone Transfer Scanner": {"vulnerable": True, "records": []},
                },
            },
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        assert summary.critical == 1  # Subdomain takeover
        assert summary.high == 1  # Zone transfer
        assert summary.total == 2
    
    def test_error_handling(self):
        """Test that errors in scan data don't cause crashes."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "CORS Scanner": {"error": "Connection timeout"},
                    "Host Header Injection": {"error": "Failed"},
                },
            }
        }
        
        scorer = SeverityScorer()
        summary = scorer.analyze(results)
        
        # Errors should be skipped, not counted
        assert summary.total == 0


class TestGetSeveritySummary:
    """Test convenience function."""
    
    def test_convenience_function(self):
        """Test get_severity_summary works correctly."""
        results = {
            "example.com": {
                "target": {},
                "scans": {
                    "Subdomain Takeover": {"vulnerable": True, "provider": "S3", "cname": "x"},
                },
            }
        }
        
        summary = get_severity_summary(results)
        
        assert isinstance(summary, SeveritySummary)
        assert summary.critical == 1
