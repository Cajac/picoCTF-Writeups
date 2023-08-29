# extensions

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 150
Tags: picoCTF 2019, Forensics
Author:  SANJAY C/DANNY
 
Description:
This is a really weird text file TXT? Can you find the flag?

Hints:
1. How do operating systems know what kind of file it is? (It's not just the ending!
2. Make sure to submit the flag as picoCTF{XXXXX}
```

## Solution

Lets start by checking the file with `file`.
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/Forensics/Extensions]
└─$ file flag.txt 
flag.txt: PNG image data, 1697 x 608, 8-bit/color RGB, non-interlaced
```

Ah, it's a PNG picture file, not a text file.

To view the flag use a tool such as `eog` of `feh`.

For additional information, please see the references below.

## References

- [Wikipedia - Filename extension](https://en.wikipedia.org/wiki/Filename_extension)
