"""
Diff Utility for comparing scan results.

Compares current scan results against a baseline to identify:
- New findings (appeared since baseline)
- Resolved findings (no longer present)
- Changed findings (values differ)
- Unchanged findings

Supports JSON baseline files.
"""

import json
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum


class ChangeType(str, Enum):
    """Types of changes between scans."""
    NEW = "new"
    REMOVED = "removed"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


@dataclass
class DiffResult:
    """Result of comparing two scans."""
    host: str
    module: str
    change_type: ChangeType
    key: str
    old_value: Any = None
    new_value: Any = None
    severity: str = "info"


class ScanDiffer:
    """Compares scan results to find differences."""

    def __init__(self):
        # Modules with security-relevant fields to track
        self.security_modules = {
            "Port Scanner": ["open_ports"],
            "WAF Detection": ["detected", "wafs"],
            "Security Headers": ["score", "missing"],
            "CORS Scanner": ["vulnerable", "vulnerabilities"],
            "Subdomain Takeover": ["vulnerable"],
            "Sensitive File Fuzzer": ["found"],
            "JS Secret Scanner": ["secrets"],
            "Vuln Scanner": None,  # Compare all keys
            "Open Redirect Scanner": ["vulnerable", "vulnerabilities"],
            "HTTP Method Scanner": ["dangerous_methods", "vulnerabilities"],
            "API Scanner": ["security_issues", "discovered_endpoints"],
        }

    def diff(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
    ) -> Dict[str, List[DiffResult]]:
        """
        Compare baseline and current scan results.
        
        Returns dict mapping host to list of differences.
        """
        all_diffs = {}

        # Get all hosts from both scans
        all_hosts = set(baseline.keys()) | set(current.keys())

        for host in all_hosts:
            host_diffs = []

            baseline_data = baseline.get(host, {})
            current_data = current.get(host, {})

            # Host removed
            if host not in current:
                host_diffs.append(DiffResult(
                    host=host,
                    module="Target",
                    change_type=ChangeType.REMOVED,
                    key="host",
                    old_value=host,
                    severity="info",
                ))
                all_diffs[host] = host_diffs
                continue

            # Host added
            if host not in baseline:
                host_diffs.append(DiffResult(
                    host=host,
                    module="Target",
                    change_type=ChangeType.NEW,
                    key="host",
                    new_value=host,
                    severity="info",
                ))

            # Compare scans
            baseline_scans = baseline_data.get("scans", {})
            current_scans = current_data.get("scans", {})

            module_diffs = self._compare_modules(host, baseline_scans, current_scans)
            host_diffs.extend(module_diffs)

            if host_diffs:
                all_diffs[host] = host_diffs

        return all_diffs

    def _compare_modules(
        self,
        host: str,
        baseline_scans: Dict[str, Any],
        current_scans: Dict[str, Any],
    ) -> List[DiffResult]:
        """Compare all modules between baseline and current."""
        diffs = []

        all_modules = set(baseline_scans.keys()) | set(current_scans.keys())

        for module in all_modules:
            baseline_data = baseline_scans.get(module, {})
            current_data = current_scans.get(module, {})

            # Skip if both are empty or have errors
            if self._is_empty_or_error(baseline_data) and self._is_empty_or_error(current_data):
                continue

            # Get fields to compare
            if module in self.security_modules:
                fields = self.security_modules[module]
            else:
                fields = None  # Compare all

            module_diffs = self._compare_data(
                host, module, baseline_data, current_data, fields
            )
            diffs.extend(module_diffs)

        return diffs

    def _compare_data(
        self,
        host: str,
        module: str,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
        fields: List[str] = None,
    ) -> List[DiffResult]:
        """Compare data between baseline and current for specific fields."""
        diffs = []

        if fields is None:
            # Compare all keys
            fields = list(set(baseline.keys()) | set(current.keys()))
            fields = [f for f in fields if not f.startswith("_") and f != "error"]

        for field in fields:
            old_val = baseline.get(field)
            new_val = current.get(field)

            if old_val == new_val:
                continue

            # Determine change type and severity
            change_type, severity = self._classify_change(
                module, field, old_val, new_val
            )

            diffs.append(DiffResult(
                host=host,
                module=module,
                change_type=change_type,
                key=field,
                old_value=old_val,
                new_value=new_val,
                severity=severity,
            ))

        return diffs

    def _classify_change(
        self,
        module: str,
        field: str,
        old_val: Any,
        new_val: Any,
    ) -> Tuple[ChangeType, str]:
        """Classify the type and severity of a change."""
        # Determine change type
        if old_val is None or (isinstance(old_val, (list, dict)) and not old_val):
            change_type = ChangeType.NEW
        elif new_val is None or (isinstance(new_val, (list, dict)) and not new_val):
            change_type = ChangeType.REMOVED
        else:
            change_type = ChangeType.CHANGED

        # Determine severity based on module and field
        severity = "info"

        # High severity: new vulnerabilities or security issues
        high_severity_fields = [
            "vulnerable", "vulnerabilities", "security_issues", 
            "secrets", "dangerous_methods",
        ]
        if field in high_severity_fields and change_type == ChangeType.NEW:
            severity = "high"
        elif field in high_severity_fields and change_type == ChangeType.REMOVED:
            severity = "low"  # Good news - issue resolved

        # Medium severity: new open ports, new endpoints
        medium_severity_fields = ["open_ports", "discovered_endpoints", "found"]
        if field in medium_severity_fields and change_type == ChangeType.NEW:
            severity = "medium"

        # Security score changes
        if field == "score":
            if isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
                if new_val < old_val:
                    severity = "medium"  # Score decreased
                elif new_val > old_val:
                    severity = "low"  # Score improved

        return change_type, severity

    def _is_empty_or_error(self, data: Any) -> bool:
        """Check if data is empty or just an error."""
        if not data:
            return True
        if isinstance(data, dict):
            if "error" in data and len(data) == 1:
                return True
            if data.get("status") == "crashed":
                return True
        return False

    def generate_summary(self, diffs: Dict[str, List[DiffResult]]) -> Dict[str, Any]:
        """Generate summary statistics for the diff."""
        total_new = 0
        total_removed = 0
        total_changed = 0
        high_severity = 0
        medium_severity = 0

        by_module = {}

        for host, host_diffs in diffs.items():
            for diff in host_diffs:
                if diff.change_type == ChangeType.NEW:
                    total_new += 1
                elif diff.change_type == ChangeType.REMOVED:
                    total_removed += 1
                elif diff.change_type == ChangeType.CHANGED:
                    total_changed += 1

                if diff.severity == "high":
                    high_severity += 1
                elif diff.severity == "medium":
                    medium_severity += 1

                # Track by module
                if diff.module not in by_module:
                    by_module[diff.module] = {"new": 0, "removed": 0, "changed": 0}
                by_module[diff.module][diff.change_type.value] = (
                    by_module[diff.module].get(diff.change_type.value, 0) + 1
                )

        return {
            "total_changes": total_new + total_removed + total_changed,
            "new": total_new,
            "removed": total_removed,
            "changed": total_changed,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "hosts_affected": len(diffs),
            "by_module": by_module,
        }


def load_baseline(filepath: str) -> Dict[str, Any]:
    """Load baseline from JSON file."""
    with open(filepath, "r") as f:
        return json.load(f)


def save_baseline(results: Dict[str, Any], filepath: str):
    """Save results as baseline JSON file."""
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)
