# strings it

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2019, General Skills
Author: SANJAY C/DANNY TUNITIS

Description:
Can you find the flag in file without running it?

Hints:
1. strings
```

## Solution

This is basically a tutorial to usage of `strings` and `grep`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/General_Skills/Strings_it]
└─$ strings -n 8 strings | grep picoCTF
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [strings(1) - Linux man page](https://linux.die.net/man/1/strings)
- [grep(1) - Linux man page](https://linux.die.net/man/1/grep)
