Granny Writeup
==============

Enumeration
-----------

### Nmap

```
# Nmap 7.70 scan initiated Thu Apr 18 17:19:36 2019 as: nmap -A -p- -o nmap 10.10.10.15
Nmap scan report for 10.10.10.15
Host is up (0.073s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unkown
|   Server Date: Fri, 19 Apr 2019 00:16:28 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 18 17:21:30 2019 -- 1 IP address (1 host up) scanned in 115.01 seconds
```

### Gobuster

```
/_private (Status: 301)
/_vti_bin (Status: 301)
/_vti_bin/_vti_adm/admin.dll (Status: 200)
/_vti_bin/shtml.dll (Status: 200)
/_vti_bin/_vti_aut/author.dll (Status: 200)
/_vti_log (Status: 301)
/aspnet_client (Status: 301)
/images (Status: 301)
/Images (Status: 301)
```

### Nikto

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.15
+ Target Hostname:    granny.htb
+ Target Port:        80
+ Start Time:         2019-04-18 17:28:10 (GMT-7)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.
+ OSVDB-5646: HTTP method 'DELETE' allows clients to delete files on the web server.
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (SEARCH PROPPATCH PROPFIND COPY MKCOL UNLOCK LOCK listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://granny/_vti_bin/_vti_aut/author.dll
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_private/: FrontPage directory found.
+ OSVDB-3233: /_vti_bin/: FrontPage directory found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3300: /_vti_bin/: shtml.exe/shtml.dll is available remotely. Some versions of the Front Page ISAPI filter are vulnerable to a DOS (not attempted).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 7940 requests: 0 error(s) and 32 item(s) reported on remote host
+ End Time:           2019-04-18 17:38:55 (GMT-7) (645 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Davtest

```
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://granny.htb
********************************************************
NOTE    Random string for this session: DcKtLl4hiHEKy
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://granny.htb/DavTestDir_DcKtLl4hiHEKy
********************************************************
 Sending test files
PUT     jsp     SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.jsp
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.txt
PUT     shtml   FAIL
PUT     php     SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.php
PUT     cgi     FAIL
PUT     jhtml   SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.jhtml
PUT     html    SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.html
PUT     cfm     SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.cfm
PUT     pl      SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.pl
PUT     aspx    FAIL
PUT     asp     FAIL
********************************************************
 Checking for test file execution
EXEC    jsp     FAIL
EXEC    txt     SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.txt
EXEC    php     FAIL
EXEC    jhtml   FAIL
EXEC    html    SUCCEED:        http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.html
EXEC    cfm     FAIL
EXEC    pl      FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://granny.htb/DavTestDir_DcKtLl4hiHEKy
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.jsp
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.txt
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.php
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.jhtml
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.html
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.cfm
PUT File: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.pl
Executes: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.txt
Executes: http://granny.htb/DavTestDir_DcKtLl4hiHEKy/davtest_DcKtLl4hiHEKy.html
```

Getting User
------------

### MSF Privesc

```
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```

### Listening Ports

```
c:\windows\system32\inetsrv>netstat -nao | findstr LISTENING
netstat -nao | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       668
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1025           0.0.0.0:0              LISTENING       952
  TCP    0.0.0.0:1027           0.0.0.0:0              LISTENING       408
  TCP    0.0.0.0:5859           0.0.0.0:0              LISTENING       4
  TCP    10.10.10.15:139        0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:1028         0.0.0.0:0              LISTENING       1884
```

Getting Root
------------




