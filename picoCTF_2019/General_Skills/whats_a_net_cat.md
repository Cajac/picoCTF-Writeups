# what's a net cat?

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2019, General Skills
Author: SANJAY C/DANNY TUNITIS
 
Description:
Using netcat (nc) is going to be pretty important. 

Can you connect to jupiter.challenges.picoctf.org at port 64287 to get the flag?

Hints:
1. nc tutorial
```

## Solution

This is basically a tutorial to the basic syntax of `nc` usage
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/General_Skills/What's_a_net_cat]
└─$ nc jupiter.challenges.picoctf.org 64287 
You're on your way to becoming the net cat master
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [nc(1) - Linux man page](https://linux.die.net/man/1/nc)
