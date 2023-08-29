# What Lies Within

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 150
Tags: picoCTF 2019, Forensics
Author: JULIO/DANNY

Description:
There's something in the building. Can you retrieve the flag?

Hints:
1. There is data encoded somewhere... there might be an online decoder.
```

## Solution

There are several ways to solve this challenge and here are two of them.

### Using an online service

We can use [stylesuxx steganography online](http://stylesuxx.github.io/steganography/#decode) service to solve this.

Click `Choose File` and select the file. Then press the `Decode` button to get the flag.

### Using zsteg

We can also use [zsteg](https://github.com/zed-0xff/zsteg) to solve this
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/Forensics/What_Lies_Within]
└─$ zsteg buildings.png 
b1,r,lsb,xy         .. text: "^5>R5YZrG"
b1,rgb,lsb,xy       .. text: "picoCTF{<REDACTED>}"        <----- Here
b1,abgr,msb,xy      .. file: PGP Secret Sub-key -
b2,b,lsb,xy         .. text: "XuH}p#8Iy="
b3,abgr,msb,xy      .. text: "t@Wp-_tH_v\r"
b4,r,lsb,xy         .. text: "fdD\"\"\"\" "
b4,r,msb,xy         .. text: "%Q#gpSv0c05"
b4,g,lsb,xy         .. text: "fDfffDD\"\""
b4,g,msb,xy         .. text: "f\"fff\"\"DD"
b4,b,lsb,xy         .. text: "\"$BDDDDf"
b4,b,msb,xy         .. text: "wwBDDDfUU53w"
b4,rgb,msb,xy       .. text: "dUcv%F#A`"
b4,bgr,msb,xy       .. text: " V\"c7Ga4"
b4,abgr,msb,xy      .. text: "gOC_$_@o"
```

For additional information, please see the references below.

## References

- [Wikipedia - Steganography](https://en.wikipedia.org/wiki/Steganography)
- [zsteg](https://github.com/zed-0xff/zsteg)
