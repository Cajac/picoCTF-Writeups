# DISKO 1

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Points: 1
Tags: Challenge Library Exclusive, Forensics
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Darkraicg492

Description:
Can you find the flag in this disk image?

Download the disk image here.

Hints:
1. Maybe Strings could help? If only there was a way to do that?
```

Challenge link: [https://learn.cylabacademy.org/library/505](https://learn.cylabacademy.org/library/505)

## Solution

### Unpacking and basic disk analysis

We start by unpacking the disk image and check the disk type

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_1]
└─$ ls -l              
total 20005
-rwxrwxrwx 1 root root 20484476 Jun 29 18:30 disko-1.dd.gz

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_1]
└─$ gzip -d disko-1.dd.gz 
gzip: disko-1.dd: Value too large for defined data type

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_1]
└─$ ls -la
total 51200
drwxrwxrwx 1 root root        0 Jun 29 18:35 .
drwxrwxrwx 1 root root        0 Jun 29 18:26 ..
-rwxrwxrwx 1 root root 52428800 Jun 29 18:30 disko-1.dd

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_1]
└─$ file disko-1.dd            
disko-1.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "mkfs.fat", Media descriptor 0xf8, sectors/track 32, heads 8, sectors 102400 (volumes > 32 MB), FAT (32 bit), sectors/FAT 788, serial number 0x241a4420, unlabeled
```

We have a disk with a MBR boot sector and a FAT32 file system.

### Get the flag

To get the flag, we can extract all the strings and grep for the flag

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_1]
└─$ strings -n 8 disko-1.dd | grep picoCTF          
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [File Allocation Table - Wikipedia](https://en.wikipedia.org/wiki/File_Allocation_Table)
- [File system - Wikipedia](https://en.wikipedia.org/wiki/File_system)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [gzip - Linux manual page](https://linux.die.net/man/1/gzip)
- [Master boot record - Wikipedia](https://en.wikipedia.org/wiki/Master_boot_record)
- [String (computer science) - Wikipedia](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [The Sleuth Kit - Tool Overview](https://wiki.sleuthkit.org/TSK-Tool-Overview/)
- [The Sleuth Kit - Commands](https://wiki.sleuthkit.org/The-Sleuth-Kit-commands/)
