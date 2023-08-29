# So Meta

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 150
Tags: picoCTF 2019, Forensics
Author:  KEVIN COOPER/DANNY
 
Description:
Find the flag in this picture.

Hints:
1. What does meta mean in the context of files?
2. Ever heard of metadata?
```

## Solution

In steganography oriented forensics challenges there are a number of checks that are more or less "standard practice".  
These include:
1. Checking for metadata with [ExifTool](https://exiftool.org/)
2. Checking for embedded strings
3. Checking for embedded Zip-files with tools such as [Binwalk ](https://github.com/ReFirmLabs/binwalk)

Lets start checking them one by one until we find the flag.

### Checking for metadata

First, check for metadata with `exiftool`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/Forensics/So_Meta]
└─$ exiftool pico_img.png                  
ExifTool Version Number         : 12.52
File Name                       : pico_img.png
Directory                       : .
File Size                       : 109 kB
File Modification Date/Time     : 2019:09:29 03:19:36-04:00
File Access Date/Time           : 2023:08:04 13:52:17-04:00
File Inode Change Date/Time     : 2019:09:29 03:19:36-04:00
File Permissions                : -rwxrwxrwx
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 600
Image Height                    : 600
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Software                        : Adobe ImageReady
XMP Toolkit                     : Adobe XMP Core 5.3-c011 66.145661, 2012/02/06-14:56:27
Creator Tool                    : Adobe Photoshop CS6 (Windows)
Instance ID                     : xmp.iid:A5566E73B2B811E8BC7F9A4303DF1F9B
Document ID                     : xmp.did:A5566E74B2B811E8BC7F9A4303DF1F9B
Derived From Instance ID        : xmp.iid:A5566E71B2B811E8BC7F9A4303DF1F9B
Derived From Document ID        : xmp.did:A5566E72B2B811E8BC7F9A4303DF1F9B
Warning                         : [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
Artist                          : picoCTF{<REDACTED>}
Image Size                      : 600x600
Megapixels                      : 0.360
```

And there in the `Artist` field we have the flag.

For additional information, please see the references below.

## References

- [Wikipedia - Metadata](https://en.wikipedia.org/wiki/Metadata)
- [Wikipedia - Exif](https://en.wikipedia.org/wiki/Exif)
- [Wikipedia - ExifTool](https://en.wikipedia.org/wiki/ExifTool)
