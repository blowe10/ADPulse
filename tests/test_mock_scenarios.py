#!/usr/bin/env python3
"""
Mock test suite for ADPulse checks (36-53)
Simulates real AD scenarios without requiring a live domain
"""

import sys
import json
from typing import List, Dict, Any
from dataclasses import dataclass
from unittest.mock import Mock, MagicMock

sys.path.insert(0, "..")

# Mock AD response
@dataclass
class MockLDAPEntry:
    """Mock LDAP entry for testing"""
    dn: str
    attributes: Dict[str, List[Any]]
    
    def __getattr__(self, name):
        if name in self.attributes:
            return MockAttribute(self.attributes[name])
        raise AttributeError(f"No attribute {name}")

class MockAttribute:
    """Mock LDAP attribute"""
    def __init__(self, values):
        self.values = values if isinstance(values, list) else [values]
        self.raw_values = self.values
    
    def __bool__(self):
        return len(self.values) > 0
    
    def __str__(self):
        return str(self.values[0]) if self.values else ""

class MockADConnector:
    """Mock AD Connector for testing without live domain"""
    
    def __init__(self):
        self.base_dn = "dc=example,dc=com"
        self.config_dn = f"CN=Configuration,{self.base_dn}"
        self.entries = []
        self.conn = Mock()
        self.conn.entries = []
    
    def attr_str(self, entry, attr):
        """Mock attr_str method"""
        if not entry or attr not in entry.attributes:
            return None
        vals = entry.attributes[attr]
        return str(vals[0]) if vals else None
    
    def attr_int(self, entry, attr):
        """Mock attr_int method"""
        if not entry or attr not in entry.attributes:
            return 0
        vals = entry.attributes[attr]
        return int(vals[0]) if vals else 0
    
    def search(self, filter_str, attrs, **kwargs):
        """Mock search returning test data"""
        # This will be populated with specific test scenarios
        return self.entries
    
    def resolve_sid(self, sid):
        """Mock SID resolution"""
        sid_map = {
            "S-1-5-21-3623811015-3361044348-30300510-513": "Domain Users",
            "S-1-5-21-3623811015-3361044348-30300510-512": "Domain Admins",
            "S-1-5-32-551": "Backup Operators",
            "S-1-5-32-549": "Server Operators",
            "S-1-5-18": "SYSTEM",
        }
        return sid_map.get(sid, f"Unknown({sid[-3:]})")


def create_cert_template_risky_acl_scenario():
    """Scenario: Certificate template with write ACL for non-admin"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,dc=example,dc=com",
            {
                "cn": ["User"],
                "distinguishedName": ["CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,dc=example,dc=com"],
            }
        )
    ]
    return ad


def create_operator_group_scenario():
    """Scenario: Non-admin users in operator groups"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN=john.smith,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["john.smith"],
                "adminCount": [0],
                "userAccountControl": [512],  # Normal account
            }
        ),
        MockLDAPEntry(
            "CN=jane.doe,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["jane.doe"],
                "adminCount": [1],
                "userAccountControl": [512],  # Admin account
            }
        ),
    ]
    return ad


def create_ldap_password_scenario():
    """Scenario: Plaintext passwords in LDAP"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN=svc-account,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["svc-account"],
                "adminCount": [1],
                "userPassword": ["P@ssw0rd123!"],  # CRITICAL ISSUE
            }
        ),
    ]
    return ad


def create_computer_write_acl_scenario():
    """Scenario: Computer objects with write ACL"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN=DESKTOP-ABC123,CN=Computers,dc=example,dc=com",
            {
                "cn": ["DESKTOP-ABC123"],
                "distinguishedName": ["CN=DESKTOP-ABC123,CN=Computers,dc=example,dc=com"],
            }
        ),
        MockLDAPEntry(
            "CN=SERVER-XYZ,CN=Computers,dc=example,dc=com",
            {
                "cn": ["SERVER-XYZ"],
                "distinguishedName": ["CN=SERVER-XYZ,CN=Computers,dc=example,dc=com"],
            }
        ),
    ]
    return ad


def create_disabled_admin_scenario():
    """Scenario: Disabled admin accounts (hygiene issue)"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN=old-admin1,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["old-admin1"],
                "adminCount": [1],
                "userAccountControl": [514],  # ACCOUNTDISABLE (0x2) | NORMAL (0x200)
                "pwdLastSet": [131000000000000000],  # Old date (~2018)
                "displayName": ["Old Admin 1"],
            }
        ),
        MockLDAPEntry(
            "CN=legacy-da,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["legacy-da"],
                "adminCount": [1],
                "userAccountControl": [514],  # Disabled
                "pwdLastSet": [0],  # Never set
                "displayName": ["Legacy Domain Admin"],
            }
        ),
    ]
    return ad


def create_aad_connect_scenario():
    """Scenario: Azure AD Connect accounts detected"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN=MSOL_123456,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["MSOL_123456"],
                "adminCount": [0],
                "userAccountControl": [66048],  # Normal sync account
                "description": ["AAD Connect Synchronization Account"],
            }
        ),
        MockLDAPEntry(
            "CN=ADSync_Service,CN=Users,dc=example,dc=com",
            {
                "sAMAccountName": ["ADSync_Service"],
                "adminCount": [1],  # RISKY!
                "userAccountControl": [512],
                "description": ["Azure AD Sync Service"],
            }
        ),
    ]
    return ad


def create_gpo_scenario():
    """Scenario: Group Policy Objects"""
    ad = MockADConnector()
    ad.entries = [
        MockLDAPEntry(
            "CN={12345678-1234-1234-1234-123456789012},CN=Policies,CN=System,dc=example,dc=com",
            {
                "cn": ["{12345678-1234-1234-1234-123456789012}"],
                "displayName": ["Security Baseline GPO"],
                "distinguishedName": ["CN={12345678-1234-1234-1234-123456789012},CN=Policies,CN=System,dc=example,dc=com"],
            }
        ),
    ]
    return ad


def run_scenario_tests():
    """Run all test scenarios"""
    print("\n" + "=" * 80)
    print("ADPulse Mock Test Suite - Check Scenarios")
    print("=" * 80)
    
    scenarios = {
        "Check #43 - ESC4 Cert Template Write": create_cert_template_risky_acl_scenario,
        "Check #44 - Operator Groups": create_operator_group_scenario,
        "Check #46 - LDAP Passwords": create_ldap_password_scenario,
        "Check #42 - Computer Write ACL": create_computer_write_acl_scenario,
        "Check #49 - Disabled Admin Accounts": create_disabled_admin_scenario,
        "Check #53 - AAD Connect Accounts": create_aad_connect_scenario,
        "Check #50 - GPO Objects": create_gpo_scenario,
    }
    
    results = {}
    
    for name, scenario_fn in scenarios.items():
        print(f"\n► Testing: {name}")
        print("-" * 80)
        
        try:
            ad = scenario_fn()
            entries = ad.search("*", ["*"])
            
            print(f"  ✅ Mock scenario created")
            print(f"  📊 Entries generated: {len(entries)}")
            
            # Print sample entries
            for i, entry in enumerate(entries[:3]):
                print(f"  📌 Entry {i+1}: {entry.dn}")
                for attr, vals in list(entry.attributes.items())[:3]:
                    print(f"     • {attr}: {vals[0]}")
            
            results[name] = "✅ PASS"
        
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results[name] = f"❌ FAIL: {e}"
    
    # Summary
    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    
    passed = sum(1 for v in results.values() if "PASS" in v)
    total = len(results)
    
    for name, result in results.items():
        symbol = "✅" if "PASS" in result else "❌"
        print(f"{symbol} {name}: {result}")
    
    print(f"\n📊 Results: {passed}/{total} scenarios passed ({100*passed//total}%)")
    
    if passed == total:
        print("\n✅ All mock test scenarios ready for next phase!")
        print("   Next: Run actual checks against mock data")
    
    return passed == total


if __name__ == "__main__":
    success = run_scenario_tests()
    sys.exit(0 if success else 1)
