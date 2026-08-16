# Riddle Registry

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Points: 50
Tags: Forensics, picoMini by CMU-Africa, browser_webshell_solvable
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Prince Niyonshuti N.

Description:
Hi, intrepid investigator! 📄🔍 You've stumbled upon a peculiar PDF filled with what seems like nothing more than 
garbled nonsense. But beware! Not everything is as it appears. Amidst the chaos lies a hidden treasure—an elusive 
flag waiting to be uncovered.

Find the PDF file here Hidden Confidential Document and uncover the flag within the metadata.

Hints:
1. Don't be fooled by the visible text; it’s just a decoy!
2. Look beyond the surface for hidden clues
```

Challenge link: [https://learn.cylabacademy.org/library/530](https://learn.cylabacademy.org/library/530)

## Solution

### Basic file analysis

We start with some basic file analysis of the document.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Riddle_Registry]
└─$ file confidential.pdf 
confidential.pdf: PDF document, version 1.7, 1 page(s)

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Riddle_Registry]
└─$ exiftool confidential.pdf 
ExifTool Version Number         : 13.50
File Name                       : confidential.pdf
Directory                       : .
File Size                       : 183 kB
File Modification Date/Time     : 2026:07:16 07:03:19+02:00
File Access Date/Time           : 2026:07:16 07:03:19+02:00
File Inode Change Date/Time     : 2026:07:16 07:03:19+02:00
File Permissions                : -rwxrwxrwx
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 1
Producer                        : PyPDF2
Author                          : cGljb0NURntwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV9mOTQzMDBjNH0=
```

The Author field look strange, like [Base64-encoded]((https://en.wikipedia.org/wiki/Base64)) data.

### Get the flag

Let's extract and decode it.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Riddle_Registry]
└─$ exiftool -T -Author confidential.pdf
cGljb0NURntwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV9mOTQzMDBjNH0=

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Riddle_Registry]
└─$ exiftool -T -Author confidential.pdf | base64 -d
picoCTF{<REDACTED>}  
```

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [ExifTool - Homepage](https://exiftool.org/)
- [exiftool - Linux manual page](https://linux.die.net/man/1/exiftool)
- [ExifTool - Wikipedia](https://en.wikipedia.org/wiki/ExifTool)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [Metadata - Wikipedia](https://en.wikipedia.org/wiki/Metadata)
