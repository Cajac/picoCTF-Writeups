# HideToSee

- [Challenge information](HideToSee.md#challenge-information)
- [Solution](HideToSee.md#solution)
  - [Checking for metadata](HideToSee.md#checking-for-metadata)
  - [Checking for embedded strings](HideToSee.md#checking-for-embedded-strings)
  - [Checking for embedded Zip-files](HideToSee.md#checking-for-embedded-zip-files)
  - [Checking for hidden files](HideToSee.md#checking-for-hidden-files)
  - [Get the flag](HideToSee.md#get-the-flag)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, Cryptography
Author: SUNDAY JACOB NWANYIM

Description:
How about some hide and seek heh?

Look at this image here.

Hints:
1. Download the image and try to extract it.
```

## Solution

The challange name (Hide something) suggests there are steganography involved.  
Also the name of the given file (atbash.jpg) suggests that the [Atbash substitution cipher](https://en.wikipedia.org/wiki/Atbash) is used to encode the flag.

In steganography challenges there are a number of checks that are more or less "standard practice". These include:
1. Checking for metadata with [ExifTool](https://exiftool.org/)
2. Checking for embedded strings
3. Checking for "forensically" embedded Zip-files with tools such as [Binwalk ](https://github.com/ReFirmLabs/binwalk)
4. Checking for "staganography" hidden files with tools such as [steghide](https://steghide.sourceforge.net/)

Lets start by running through these standard checks one-by-one until we find the flag.

### Checking for metadata

Checking for metadata with `exiftool`
```
Z:\CTFs\picoCTF\picoCTF_2023\Cryptography\HideToSee>exiftool atbash.jpg
ExifTool Version Number         : 12.44
File Name                       : atbash.jpg
Directory                       : .
File Size                       : 51 kB
File Modification Date/Time     : 2023:07:19 07:38:06+02:00
File Access Date/Time           : 2023:07:19 07:38:33+02:00
File Creation Date/Time         : 2023:07:19 07:38:03+02:00
File Permissions                : -rw-rw-rw-
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 465
Image Height                    : 455
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 465x455
Megapixels                      : 0.212
```

Nope, nothing of interest.

### Checking for embedded strings

Continue with checking for strings. In this case I'm using a [Windows version of strings from Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/strings).
```
Z:\CTFs\picoCTF\picoCTF_2023\Cryptography\HideToSee>strings -n 8 atbash.jpg

Strings v2.53 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

 , #&')*)
-0-(0%()(
((((((((((((((((((((((((((((((((((((((((((((((((((
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
K+ #9=O_j
&~oc_$xb
o-X43(e#
Tpr:sYz_
me^sZ"$udv
4*Kzq_.x
TW2.M V
WzwdI^V<
<Mkmsw9U
h(&2[x/K
```

Nope, nothing of interest here either.

### Checking for embedded Zip-files

Now lets check for embedded Zip-files or other interesting files with `binwalk`
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/Cryptography/HideToSee]
└─$ binwalk atbash.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
```

Nope, fail again.

### Checking for hidden files

The previous check looked for "foresically" embedded/hidden files.  
This check looks for "staganography" hidden/embedded files with tools such as `steghide`.

Lets use the 'extract' command in `steghide` and specifying the stegofile with -sf.
```
Z:\CTFs\picoCTF\picoCTF_2023\Cryptography\HideToSee>steghide extract -sf atbash.jpg
Enter passphrase:
wrote extracted data to "encrypted.txt".
```

Since we don't have any password just press enter when prompted.
Yes, there is indeed a hidden file call `encrypted.txt`.

Lets view it
```
Z:\CTFs\picoCTF\picoCTF_2023\Cryptography\HideToSee>type encrypted.txt
krxlXGU{zgyzhs_xizxp_92533667}
```

Ah, a flag most likely scrambled with the Atbash cipher.

### Get the flag

To view the flag in plaintext you can use one of these sites
 * The [Atbash cipher recipe from CyberChef](https://cyberchef.org/#recipe=Atbash_Cipher())
 * The [Atbash cipher function at Crypto Corner](https://crypto.interactive-maths.com/atbash-cipher.html)
