# ADPulse New Security Checks (36-41)

This document describes the 6 new security checks added to ADPulse, expanding coverage from 35 to 41 total checks.

## Check #36: gMSA ACL Exposure Detection

**Category:** Service Accounts  
**Severity:** HIGH  
**Risk Score:** 15 points

### Description
Detects Group Managed Service Accounts (gMSA) with overly permissive Access Control Lists (ACLs). Non-privileged principals should never have write access to gMSA objects, as this allows them to read/modify service account passwords.

### What It Checks
- Enumerates all `msDS-GroupManagedServiceAccount` objects
- Parses the binary DACL (nTSecurityDescriptor) on each gMSA
- Flags non-privileged accounts with write permissions (GENERIC_ALL, GENERIC_WRITE, WRITE_PROP)
- Reports resolved account names and access masks

### Remediation
Restrict gMSA ACLs to authorized service accounts and Domain Admins only via:
```powershell
Get-ADServiceAccount -Identity "MyGMSA" | Set-ADServiceAccount -Clear nTSecurityDescriptor
```

### References
- [Microsoft gMSA Documentation](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/)

---

## Check #37: PIM Gaps / AdminSDHolder Enforcement Verification

**Category:** Privileged Identity Management  
**Severity:** HIGH  
**Risk Score:** 12 points

### Description
Identifies orphaned or stale administrative accounts that are marked with `adminCount=1` but are no longer active members of privileged groups. These are artifacts of removed admins that still retain protection flags and can indicate incomplete admin offboarding.

### What It Checks
- Lists all accounts with `adminCount=1`
- Cross-references against actual privileged group membership (DA, EA, Schema Admins, Administrators)
- Detects disabled admin accounts still flagged as protected
- Flags accounts inactive for 90+ days

### Remediation
Remove orphaned accounts or re-enable legitimate ones:
```powershell
Set-ADUser -Identity "StaleAdmin" -adminCount $false
```

### References
- [Microsoft AdminSDHolder Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels)

---

## Check #38: Weak Domain Trust Authentication Methods

**Category:** Domain Trusts  
**Severity:** HIGH  
**Risk Score:** 15 points

### Description
Identifies bidirectional domain trusts that lack SID filtering or quarantine flags. Weak trust configurations enable privilege escalation across domain boundaries.

### What It Checks
- Enumerates all domain trusts via `objectClass=trustedDomain`
- Identifies bidirectional trusts (trustDirection=3)
- Flags trusts without the QUARANTINED_DOMAIN attribute
- Detects transitive trusts that allow auth flow across boundaries

### Remediation
Enable SID filtering on external trusts or convert to one-way trusts:
```powershell
Set-ADTrust -Identity "TrustName" -SelectiveAuthenticationEnabled $true
```

### References
- [Microsoft Domain Trust Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-trusts)

---

## Check #39: BitLocker Recovery Key Storage in LDAP

**Category:** Encryption  
**Severity:** CRITICAL  
**Risk Score:** 20 points

### Description
Detects BitLocker recovery keys stored in Active Directory with overly permissive ACLs. Recovery passwords should be restricted to Domain Admins and authorized recovery personnel only.

### What It Checks
- Searches for `msFVE-RecoveryInformation` objects
- Parses ACLs on recovery key containers
- Flags keys readable by Everyone, Authenticated Users, or Domain Users
- Identifies world-readable recovery password containers

### Remediation
Restrict BitLocker recovery key ACLs to DAs only or avoid storing recovery keys in LDAP entirely:
```powershell
# Restrict ACL on recovery container
$acl = Get-Acl "AD:\CN=RecoveryContainer"
$acl.Access | Where {$_.IdentityReference -match "Domain Users"} | ForEach {$acl.RemoveAccessRule($_)}
Set-Acl "AD:\CN=RecoveryContainer" $acl
```

### References
- [Microsoft BitLocker Documentation](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/)

---

## Check #40: LLMNR/mDNS Boundary Misconfiguration

**Category:** Network & Infrastructure  
**Severity:** MEDIUM  
**Risk Score:** 10 points

### Description
Detects DNS misconfigurations that could enable name spoofing attacks and examines site link replication intervals that might indicate routing issues across untrusted boundaries.

### What It Checks
- Queries DNS zones for wildcard (*) records
- Identifies aggressive site link replication intervals (<5 minutes)
- Flags configurations that might enable LLMNR/mDNS poisoning
- Assesses replication topology for boundary crossing issues

### Remediation
Remove unnecessary wildcard records and normalize replication intervals:
```powershell
# Remove wildcard DNS records
Get-DnsServerResourceRecord -ZoneName "domain.local" | Where {$_.Name -match "\*"} | Remove-DnsServerResourceRecord
```

### References
- [LLMNR/mDNS Poisoning](https://attack.mitre.org/techniques/T1557/001/)

---

## Check #41: ESC12 - Temporary Certificate Flags in Templates

**Category:** ADCS / PKI  
**Severity:** HIGH  
**Risk Score:** 15 points

### Description
Identifies certificate templates that allow temporary certificate generation (`CT_FLAG_TEMPORARY` in `msPKI-Private-Key-Flag`). This can bypass CA approval workflows and enable unauthorized certificate issuance.

### What It Checks
- Enumerates all certificate templates
- Checks for the TEMPORARY flag (0x00000002) in msPKI-Private-Key-Flag
- Excludes CA and administrative templates
- Identifies templates exploitable for privilege escalation

### Remediation
Disable the TEMPORARY flag on sensitive templates:
```powershell
# Modify template via certificates MMC or PowerShell
# Remove CT_FLAG_TEMPORARY (0x00000002) from msPKI-Private-Key-Flag
```

### References
- [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

---

## Integration Notes

### Registration
All 6 new checks are automatically registered in `run_all_checks()` and will execute in order.

### Reporting
New check stats are included in:
- **Console output** - color-coded results
- **JSON export** - machine-readable findings and stats
- **HTML report** - dedicated sections for new metrics

### Performance
- All checks use read-only LDAP queries
- Binary DACL parsing follows existing patterns
- No network probes or external calls
- Typical execution time per check: 0.5-2 seconds

### Stats Tracked

| Check | Stats Key | Description |
|-------|-----------|-------------|
| 36 | `gmsas_total`, `gmsas_with_risky_acls` | gMSA inventory and risky configurations |
| 37 | `admincount_total`, `admincount_orphaned`, `admincount_stale` | Admin account audit trail |
| 38 | `domain_trusts_total`, `trusts_weak_auth`, `trusts_transitive` | Trust configuration inventory |
| 39 | `bitlocker_recovery_keys_in_ad`, `bitlocker_keys_risky_acl` | BitLocker key storage audit |
| 40 | `dns_zones_found`, `wildcard_dns_records`, `sitelinks_risky_interval` | DNS and replication topology |
| 41 | `certificate_templates_total`, `esc12_templates` | Certificate template inventory |

---

## Testing

To test these checks against a domain:

```bash
python ADPulse.py --domain corp.local --user admin --password 'P@ssw0rd!' --report all
```

All 6 new checks will execute as part of the standard scan. Results include:
- Findings with severity ratings
- Detailed recommendations
- Security references

---

## Future Enhancements

Potential additions for future versions:
- Check #42: Computer Object Write Permissions
- Check #43: ServicePrincipalName (SPN) Collision Detection
- Check #44: Disabled User Objects with Sensitive Permissions
- Check #45: Shadow Copy (VSS) Permissions Audit
