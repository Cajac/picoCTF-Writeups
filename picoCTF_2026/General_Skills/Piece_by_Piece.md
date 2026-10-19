# Piece by Piece

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Tags: General Skills, picoCTF 2026
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Yahaya Meddy

Description:
After logging in, you will find multiple file parts in your home directory. 
These parts need to be combined and extracted to reveal the flag.

SSH to chatelaine.cylabacademy.net:40366 and login as ctf-player with password d137d16e.

Hints:
<None>
```

Challenge link: [https://learn.cylabacademy.org/library/740](https://learn.cylabacademy.org/library/740)

## Solution

We start by connecting with SSH.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Piece_by_Piece]
└─$ ssh ctf-player@chatelaine.cylabacademy.net -p 40366
The authenticity of host '[chatelaine.cylabacademy.net]:40366 ([18.190.79.158]:40366)' can't be established.
ED25519 key fingerprint is SHA256:wA7PfZ3HBheVJW53Vy8120QYomN6JJqxg1En7ItEphE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[chatelaine.cylabacademy.net]:40366' (ED25519) to the list of known hosts.
ctf-player@chatelaine.cylabacademy.net's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 7.0.0-1014-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

ctf-player@academy-chall$ ls -la
total 28
drwxr-xr-x 1 ctf-player ctf-player  20 Oct 19 10:22 .
drwxr-xr-x 1 root       root        24 Sep 23 07:00 ..
drwx------ 2 ctf-player ctf-player  34 Oct 19 10:22 .cache
-rw-r--r-- 1 root       root        70 Sep 23 07:00 .profile
-rw-r--r-- 1 ctf-player ctf-player 282 Sep 23 00:59 instructions.txt
-rw-r--r-- 1 ctf-player ctf-player  51 Sep 23 07:00 part_aa
-rw-r--r-- 1 ctf-player ctf-player  51 Sep 23 07:00 part_ab
-rw-r--r-- 1 ctf-player ctf-player  51 Sep 23 07:00 part_ac
-rw-r--r-- 1 ctf-player ctf-player  51 Sep 23 07:00 part_ad
-rw-r--r-- 1 ctf-player ctf-player  35 Sep 23 07:00 part_ae
ctf-player@academy-chall$ 
```

We have a number of flag(?) parts and some instructions.

```bash
ctf-player@academy-chall$ cat instructions.txt
Hint:

- The flag is split into multiple parts as a zipped file.
- Use Linux commands to combine the parts into one file.
- The zip file is password protected. Use this "supersecret" password to extract the zip file.
- After unzipping, check the extracted text file for the flag.


ctf-player@academy-chall$ 
```

### Create and unpack the zip file

We need to re-create the Zip-file and unpack it.

```bash
ctf-player@academy-chall$ cat part_* > flag_file.zip
ctf-player@academy-chall$ unzip flag_file.zip
Archive:  flag_file.zip
[flag_file.zip] flag.txt password: 
 extracting: flag.txt                
ctf-player@academy-chall$ 
```

### Get the flag

Now we can just `cat` the flag.

```bash
ctf-player@academy-chall$ cat flag.txt 
academy{<REDACTED>}ctf-player@academy-chall$ 
```

For additional information, please see the references below.

## References

- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [unzip - Linux manual page](https://linux.die.net/man/1/unzip)
