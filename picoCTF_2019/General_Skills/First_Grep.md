# First Grep

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2019, General Skills
Author: ALEX FULTON/DANNY TUNITIS

Description:
Can you find the flag in file? 

This would be really tedious to look through manually, something tells me there is a better way.
 
Hints:
1. grep tutorial
```

## Solution

This is basically a very easy tutorial for `grep`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/General_Skills/First_Grep]
└─$ grep picoCTF file
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [grep(1) - Linux man page](https://linux.die.net/man/1/grep)
- [Grep and Regular Expressions!](https://ryanstutorials.net/linuxtutorial/grep.php)
