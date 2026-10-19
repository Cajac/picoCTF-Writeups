# SUDO MAKE ME A SANDWICH

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
Can you read the flag? I think you can!

ssh -p 14012 ctf-player@chatelaine.cylabacademy.net using password 98cb1be0

Hints:
1. What is sudo?
2. How do you know what permission you have?
```

Challenge link: [https://learn.cylabacademy.org/library/735](https://learn.cylabacademy.org/library/735)

## Solution

We start by connecting with SSH.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/SUDO_MAKE_ME_A_SANDWICH]
└─$ ssh -p 14012 ctf-player@chatelaine.cylabacademy.net
The authenticity of host '[chatelaine.cylabacademy.net]:14012 ([18.190.79.158]:14012)' can't be established.
ED25519 key fingerprint is SHA256:CizFACv90/ZG42XZjL2rD11H6dfp3lsCtzNCEnS/gr8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added '[chatelaine.cylabacademy.net]:14012' (ED25519) to the list of known hosts.
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

ctf-player@challenge:~$ ls -la
total 16
drwxr-x--- 1 ctf-player ctf-player   20 Oct 19 10:35 .
drwxr-xr-x 1 root       root         24 Sep 23 07:01 ..
-rw-r--r-- 1 ctf-player ctf-player  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 ctf-player ctf-player 3771 Mar 31  2024 .bashrc
drwx------ 2 ctf-player ctf-player   34 Oct 19 10:35 .cache
-rw-r--r-- 1 ctf-player ctf-player  807 Mar 31  2024 .profile
-r--r----- 1 root       root         31 Sep 23 07:01 flag.txt
ctf-player@challenge:~$ 
```

We can see that there is a `flag.txt` file but it's only readable by `root`.

```bash
ctf-player@challenge:~$ cat flag.txt
cat: flag.txt: Permission denied
ctf-player@challenge:~$ 
```

But we can run commands as another user with the `sudo` command.

To see what commands we can run, we can list them with `sudo -l`:

```bash
ctf-player@challenge:~$ sudo -l
Matching Defaults entries for ctf-player on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/emacs
ctf-player@challenge:~$ 
```

Ah, we can run `emacs` as all users (including `root`) without any password.

### Get the flag

To see the flag we open it with `emacs` using `sudo`:

`sudo /bin/emacs flag.txt`

```text
File Edit Options Buffers Tools Text Help
academy{<REDACTED>}




<---snip--->




-UU-:%%-  F1  flag.txt       All   L1     (Text) ----------------------------------------------------------------------------------------------------------------------------------------------------------
For information about GNU Emacs and the GNU system, type C-h C-a.
```

Press `Ctrl + X` and `Ctrl + C` to quit emacs.

For additional information, please see the references below.

## References

- [File-system permissions - Wikipedia](https://en.wikipedia.org/wiki/File-system_permissions)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
