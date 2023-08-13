# Tab, Tab, Attack

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 20
Tags: picoCTF 2021, General Skills
Author: SYREAL

Description:
Using tabcomplete in the Terminal will add years to your life, esp. when dealing with 
long rambling directory structures and filenames: Addadshashanammu.zip

Hints:
1. After `unzip`ing, this problem can be solved with 11 button-presses...(mostly Tab)...
```

## Solution

Well, this challenge is mainly an exercise in how to use [tab completion](https://en.wikipedia.org/wiki/Command-line_completion).

First we need to unpack the file with `unzip`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/General_Skills/Tab_Tab_Attack]
└─$ unzip Addadshashanammu.zip 
Archive:  Addadshashanammu.zip
   creating: Addadshashanammu/
   creating: Addadshashanammu/Almurbalarammi/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/
   creating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/
  inflating: Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku/fang-of-haynekhtnamet  
```

Then we need to change directory with `cd` to the find the file
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/General_Skills/Tab_Tab_Attack]
└─$ cd Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku 

┌──(kali㉿kali)-[/mnt/…/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku]
└─$ ls
fang-of-haynekhtnamet
```

Lets check what kind of file it is with `file`
```bash
┌──(kali㉿kali)-[/mnt/…/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku]
└─$ file fang-of-haynekhtnamet 
fang-of-haynekhtnamet: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcea24fb5379795a123bb860267d815e889a6d23, not stripped
```

Ah, a 64-bit ELF binary.

Why not run it?
```bash
┌──(kali㉿kali)-[/mnt/…/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku]
└─$ ./fang-of-haynekhtnamet                                                                                  
*ZAP!* picoCTF{<REDACTED>}
```

And there is the flag!

For additional information, please see the references below.

## References

- [Wikipredia - Command-line completion](https://en.wikipedia.org/wiki/Command-line_completion)
