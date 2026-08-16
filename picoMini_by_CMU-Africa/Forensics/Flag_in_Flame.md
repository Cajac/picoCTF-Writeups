# Flag in Flame

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Points: 100
Tags: Forensics, picoMini by CMU-Africa, browser_webshell_solvable
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Prince Niyonshuti N.

Description:
The SOC team discovered a suspiciously large log file after a recent breach. When they opened it, they found an enormous block of 
encoded text instead of typical logs. Could there be something hidden within? Your mission is to inspect the resulting file and 
reveal the real purpose of it. The team is relying on your skills to uncover any concealed information within this unusual log.

Download the encoded data here: Logs Data. 
Be prepared—the file is large, and examining it thoroughly is crucial.

Hints:
1. Use base64 to decode the data and generate the image file.
```

Challenge link: [https://learn.cylabacademy.org/library/523](https://learn.cylabacademy.org/library/523)

## Solution

### Basic file analysis

We start with some basic file analysis of the log file.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ file logs.txt 
logs.txt: ASCII text, with very long lines (65536), with no line terminators

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ wc -l logs.txt
0 logs.txt

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ xxd -l 128 logs.txt
00000000: 6956 424f 5277 304b 4767 6f41 4141 414e  iVBORw0KGgoAAAAN
00000010: 5355 6845 5567 4141 4134 4141 4141 5341  SUhEUgAAA4AAAASA
00000020: 4341 4941 4141 4168 3862 534f 4141 4541  CAIAAAAh8bSOAAEA
00000030: 4145 6c45 5156 5234 6e4f 7a39 3139 4d73  AElEQVR4nOz919Ms
00000040: 795a 556e 6950 334f 6359 2b49 464a 2b36  yZUniP3OcY+IFJ+6
00000050: 6f75 7157 4271 6f61 7574 4459 526d 4e36  ouqWBqoautDYRmN6
00000060: 656d 6661 5a6d 6c63 306d 6932 2b37 7850  emfaZmlc0mi2+7xP
00000070: 4e4a 4a2f 474a 2f34 5276 4a74 4835 646d  NJJ/GJ/4RvJtH5dm
```

As hinted in the challenge description the data looks [Base64-encoded](https://en.wikipedia.org/wiki/Base64).

Let's decode it and check the result.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ cat logs.txt| base64 -d | file -
/dev/stdin: PNG image data, 896 x 1152, 8-bit/color RGB, non-interlaced

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ cat logs.txt| base64 -d > decoded_image.png

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ 
```

We have a PNG-image.

### View the image

We can use tools such as `eog` or `feh` to view the image.

![Flag in Flame](Images/Flag_in_Flame.png)

At the bottom of the image we have a hex-encoded ASCII message.

The message is too long to manually copy. That would be tedious.

### Extract the encoded message

Let's see if we can [OCR]((https://en.wikipedia.org/wiki/Optical_character_recognition)) the message instead.

We will use `tesseract`. Install it with `sudo apt install tesseract-ocr libtesseract-dev tesseract-ocr-eng` if needed.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ tesseract -l eng decoded_image.png hexmsg  
Estimating resolution as 206

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ cat hexmsg.txt  
~.
vbw
7

ge

ry
PNW

7069636F4354467B666F72656E736963735F 616E616C797369735F69735F61 6D617A696E675F65633139383466637D

KS

“
i
```

Not perfect, but we have the message with some additional spaces and junk. We fix the rest manually.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ vi hexmsg.txt 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ cat hexmsg.txt 
7069636F4354467B666F72656E736963735F616E616C797369735F69735F616D617A696E675F65633139383466637D
```

### Get the flag

Finally, we decode the flag with `xxd`.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoMini_by_CMU-Africa/Forensics/Flag_in_Flame]
└─$ cat hexmsg.txt | xxd -r -p
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [ASCII - Wikipedia](https://en.wikipedia.org/wiki/ASCII)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [Hexadecimal - Wikipedia](https://en.wikipedia.org/wiki/Hexadecimal)
- [Optical character recognition - Wikipedia](https://en.wikipedia.org/wiki/Optical_character_recognition)
- [PNG - Wikipedia](https://en.wikipedia.org/wiki/PNG)
- [Tesseract - GitHub](https://github.com/tesseract-ocr/tesseract)
- [Tesseract - Homepage](https://tesseractocr.org/)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [xxd - Linux manual page](https://linux.die.net/man/1/xxd)
