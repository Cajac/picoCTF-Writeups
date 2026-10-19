# MY GIT

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Tags: General Skills, picoCTF 2026
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Darkraicg492

Description:
I have built my own Git server with my own rules!
git clone ssh://git@chatelaine.cylabacademy.net:38481/git/challenge.git

Here's the password: abafae1c

Check the README to get your flag!

Hints:
1. How do you specify your Git username and email?
```

Challenge link: [https://learn.cylabacademy.org/library/764](https://learn.cylabacademy.org/library/764)

## Solution

We start by cloning the repository as shown in the description.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/MY_GIT]
└─$ git clone ssh://git@chatelaine.cylabacademy.net:38481/git/challenge.git
Cloning into 'challenge'...
The authenticity of host '[chatelaine.cylabacademy.net]:38481 ([18.190.79.158]:38481)' can't be established.
ED25519 key fingerprint is SHA256:1odBG5QS6s8zkw/oWmi0D5GNF7TlseIjzjR/3WUihM4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[chatelaine.cylabacademy.net]:38481' (ED25519) to the list of known hosts.
git@chatelaine.cylabacademy.net's password: 
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (3/3), done.

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/MY_GIT]
└─$ ls
challenge

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/MY_GIT]
└─$ cd challenge    

┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ ls -la
total 5
drwxrwxrwx 1 root root    0 Oct 19 10:59 .
drwxrwxrwx 1 root root    0 Oct 19 10:59 ..
drwxrwxrwx 1 root root 4096 Oct 19 10:59 .git
-rwxrwxrwx 1 root root  155 Oct 19 10:59 README.md

┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ cat README.md   
# MyGit

### If you want the flag, make sure to push the flag!

Only flag.txt pushed by ```root:root@academy``` will be updated with the flag.

GOOD LUCK!
```

We need to [setup](https://git-scm.com/book/en/v2/Getting-Started-First-Time-Git-Setup) our `name` and `email` in a specific way to get the flag.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ git config --global user.name "root"    

┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ git config --global user.email root@academy   
```

Now we can create an empty `flag.txt` file, `add` and `commit` it.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ touch flag.txt

┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ git add flag.txt 

┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ git commit -m "Added flag.txt"                                    
[master 6e3ca66] Added flag.txt
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 flag.txt
```

### Get the flag

Finally, when we `push` the changes we get the flag.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF_2026/General_Skills/MY_GIT/challenge]
└─$ git push                      
git@xebec.cylabacademy.net's password: 
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 8 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 265 bytes | 24.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
remote: Author matched and flag.txt found in commit...
remote: Congratulations! You have successfully impersonated the root user
remote: Here's your flag: academy{<REDACTED>}
To ssh://xebec.cylabacademy.net:38481/git/challenge.git
   0afb83e..6e3ca66  master -> master
```

For additional information, please see the references below.

## References

- [Getting Started - First-Time Git Setup](https://git-scm.com/book/en/v2/Getting-Started-First-Time-Git-Setup)
- [git - Linux manual page](https://man7.org/linux/man-pages/man1/git.1.html)
- [Git - Wikipedia](https://en.wikipedia.org/wiki/Git)
- [git-add - Linux manual page](https://man7.org/linux/man-pages/man1/git-add.1.html)
- [git-clone - Linux manual page](https://man7.org/linux/man-pages/man1/git-clone.1.html)
- [git-commit - Linux manual page](https://man7.org/linux/man-pages/man1/git-commit.1.html)
- [git-config - Linux manual page](https://man7.org/linux/man-pages/man1/git-config.1.html)
- [git-push - Linux manual page](https://man7.org/linux/man-pages/man1/git-push.1.html)
- [touch - Linux manual page](https://man7.org/linux/man-pages/man1/touch.1.html)
