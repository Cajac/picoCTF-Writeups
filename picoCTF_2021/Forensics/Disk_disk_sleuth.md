# Disk, disk, sleuth!

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 110
Tags: picoCTF 2021, Forensics
Author: SYREAL

Description:
Use `srch_strings` from the sleuthkit and some terminal-fu to find a flag in this disk image: 
dds1-alpine.flag.img.gz

Hints:
1. Have you ever used `file` to determine what a file was?
2. Relevant terminal-fu in picoGym: https://play.picoctf.org/practice/challenge/85
3. Mastering this terminal-fu would enable you to find the flag in a single command: 
   https://play.picoctf.org/practice/challenge/48
4. Using your own computer, you could use qemu to boot from this disk!
```

## Solution

Lets start with unpacking the given file
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/Disk_disk_sleuth]
└─$ gunzip dds1-alpine.flag.img.gz 
gzip: dds1-alpine.flag.img: Value too large for defined data type
                                                       
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/Disk_disk_sleuth]
└─$ file dds1-alpine.flag.img 
dds1-alpine.flag.img: DOS/MBR boot sector; partition 1 : ID=0x83, active, start-CHS (0x0,32,33), end-CHS (0x10,81,1), startsector 2048, 260096 sectors
```

So we have a disk image with a MBR boot sector and one partition.

Lets search for strings in the image with either `srch_strings` or `strings`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/Disk_disk_sleuth]
└─$ strings -n 8 dds1-alpine.flag.img | grep -oE 'picoCTF{.*}'
picoCTF{<REDACTED>}
                                                         
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/Disk_disk_sleuth]
└─$ srch_strings dds1-alpine.flag.img | grep -oE 'picoCTF{.*}' 
picoCTF{<REDACTED>}
```

Both seem to work equally well and find the flag.


For additional information, please see the references below.

## References

- [Wikipedia - String (computer science)](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings(1) - Linux man page](https://linux.die.net/man/1/strings)
- [grep(1) - Linux man page](https://linux.die.net/man/1/grep)
