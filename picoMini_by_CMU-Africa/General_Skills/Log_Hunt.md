# Log Hunt

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Points: 50
Tags: General Skills, picoMini by CMU-Africa, browser_webshell_solvable
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Yahaya Meddy

Description:
Our server seems to be leaking pieces of a secret flag in its logs. The parts are scattered and sometimes repeated. 
Can you reconstruct the original flag?

Download the logs and figure out the full flag from the fragments.

Hints:
1. You can use grep to filter only matching lines from the log.
2. Some lines are duplicates; ignore extra occurrences.
```

Challenge link: [https://learn.cylabacademy.org/library/527](https://learn.cylabacademy.org/library/527)

## Solution

We start by examining the server log.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ head server.log                                                                                                                      
[1990-08-09 10:00:10] INFO FLAGPART: picoCTF{us3_
[1990-08-09 10:00:16] WARN Disk space low
[1990-08-09 10:00:19] DEBUG Cache cleared
[1990-08-09 10:00:23] WARN Disk space low
[1990-08-09 10:00:25] INFO Service restarted
[1990-08-09 10:00:33] WARN Disk space low
[1990-08-09 10:00:38] ERROR Connection lost
[1990-08-09 10:00:46] ERROR Failed login attempt
[1990-08-09 10:00:48] INFO User logged in
[1990-08-09 10:00:50] INFO User logged in

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ tail server.log                           
[1990-08-09 13:32:52] WARN Disk space low
[1990-08-09 13:32:59] ERROR Failed login attempt
[1990-08-09 13:33:01] WARN High memory usage detected
[1990-08-09 13:33:11] WARN Disk space low
[1990-08-09 13:33:20] INFO Service restarted
[1990-08-09 13:33:27] INFO Scheduled task run
[1990-08-09 13:33:28] WARN High memory usage detected
[1990-08-09 13:33:30] DEBUG System check complete
[1990-08-09 13:33:38] WARN Disk space low
[1990-08-09 13:33:47] ERROR Connection lost
```

### Extract the flag parts

Next, we use `grep` to select only the flag parts.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ grep FLAGPART server.log 
[1990-08-09 10:00:10] INFO FLAGPART: picoCTF{us3_
[1990-08-09 10:02:55] INFO FLAGPART: y0urlinux_
[1990-08-09 10:05:54] INFO FLAGPART: sk1lls_
[1990-08-09 10:05:55] INFO FLAGPART: sk1lls_
[1990-08-09 10:10:54] INFO FLAGPART: <REDACTED>}
[1990-08-09 10:10:58] INFO FLAGPART: <REDACTED>}
[1990-08-09 10:11:06] INFO FLAGPART: <REDACTED>}
[1990-08-09 11:04:27] INFO FLAGPART: picoCTF{us3_
[1990-08-09 11:04:29] INFO FLAGPART: picoCTF{us3_
[1990-08-09 11:04:37] INFO FLAGPART: picoCTF{us3_
[1990-08-09 11:09:16] INFO FLAGPART: y0urlinux_
[1990-08-09 11:09:19] INFO FLAGPART: y0urlinux_
[1990-08-09 11:12:40] INFO FLAGPART: sk1lls_
[1990-08-09 11:12:45] INFO FLAGPART: sk1lls_
[1990-08-09 11:16:58] INFO FLAGPART: <REDACTED>}
[1990-08-09 11:16:59] INFO FLAGPART: <REDACTED>}
[1990-08-09 11:17:00] INFO FLAGPART: <REDACTED>}
[1990-08-09 12:19:23] INFO FLAGPART: picoCTF{us3_
[1990-08-09 12:19:29] INFO FLAGPART: picoCTF{us3_
[1990-08-09 12:19:32] INFO FLAGPART: picoCTF{us3_
[1990-08-09 12:23:43] INFO FLAGPART: y0urlinux_
[1990-08-09 12:23:45] INFO FLAGPART: y0urlinux_
[1990-08-09 12:23:53] INFO FLAGPART: y0urlinux_
[1990-08-09 12:25:32] INFO FLAGPART: sk1lls_
[1990-08-09 12:28:45] INFO FLAGPART: <REDACTED>}
[1990-08-09 12:28:49] INFO FLAGPART: <REDACTED>}
[1990-08-09 12:28:52] INFO FLAGPART: <REDACTED>}
```

As mentioned in the challenge description the parts are present multiple times.

Let's use `cut` to extract only the flag parts.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ grep FLAGPART server.log | cut -d ' ' -f5
picoCTF{us3_
y0urlinux_
sk1lls_
sk1lls_
<REDACTED>}
<REDACTED>}
<REDACTED>}
picoCTF{us3_
picoCTF{us3_
picoCTF{us3_
y0urlinux_
y0urlinux_
sk1lls_
sk1lls_
<REDACTED>}
<REDACTED>}
<REDACTED>}
picoCTF{us3_
picoCTF{us3_
picoCTF{us3_
y0urlinux_
y0urlinux_
y0urlinux_
sk1lls_
<REDACTED>}
<REDACTED>}
<REDACTED>}
```

### Get the flag

Finally, we add `head`, `uniq` and `tr` to construct the flag.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ grep FLAGPART server.log | cut -d ' ' -f5 | head -n5
picoCTF{us3_
y0urlinux_
sk1lls_
sk1lls_
<REDACTED>}

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ grep FLAGPART server.log | cut -d ' ' -f5 | head -n5 | uniq
picoCTF{us3_
y0urlinux_
sk1lls_
<REDACTED>}

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/General_Skills/Log_Hunt]
└─$ grep FLAGPART server.log | cut -d ' ' -f5 | head -n5 | uniq | tr -d '\n'
picoCTF{<REDACTED>}  
```

For additional information, please see the references below.

## References

- [cut - Linux manual page](https://man7.org/linux/man-pages/man1/cut.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [tail - Linux manual page](https://man7.org/linux/man-pages/man1/tail.1.html)
- [tr - Linux manual page](https://man7.org/linux/man-pages/man1/tr.1.html)
- [uniq - Linux manual page](https://man7.org/linux/man-pages/man1/uniq.1.html)
