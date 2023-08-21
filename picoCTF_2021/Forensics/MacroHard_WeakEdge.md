# MacroHard WeakEdge

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 60
Tags: picoCTF 2021, Forensics
Author: MADSTACKS

Description:
I've hidden a flag in this file. Can you find it? 
Forensics is fun.pptm

Hints:
(None)
```

## Solution

The pptm (rather than just ppt) file extension and the name of the challenge hints that there are macros involved so lets check that first.

### Checking for macros

Checking for macros with `olevba` which is part of [oletools](http://www.decalage.info/python/oletools)
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ ~/python_venvs/oletools/bin/olevba Forensics_is_fun.pptm 
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.1 on Python 3.11.4 - http://decalage.info/python/oletools
===============================================================================
FILE: Forensics_is_fun.pptm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: ppt/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub not_flag()
    Dim not_flag As String
    not_flag = "sorry_but_this_isn't_it"
End Sub
No suspicious keyword or IOC found.
```

Nope, no flag there.

### Check for exif data

Next, I checked for exif data with [ExifTool](https://exiftool.org/)
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ exiftool Forensics_is_fun.pptm                          
ExifTool Version Number         : 12.52
File Name                       : Forensics_is_fun.pptm
Directory                       : .
File Size                       : 100 kB
File Modification Date/Time     : 2022:04:25 13:13:56-04:00
File Access Date/Time           : 2023:08:04 13:52:19-04:00
File Inode Change Date/Time     : 2022:04:25 13:13:56-04:00
File Permissions                : -rwxrwxrwx
File Type                       : PPTM
File Type Extension             : pptm
MIME Type                       : application/vnd.ms-powerpoint.presentation.macroEnabled.12
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0xa0517e97
Zip Compressed Size             : 674
Zip Uncompressed Size           : 10660
Zip File Name                   : [Content_Types].xml
Preview Image                   : (Binary data 2278 bytes, use -b option to extract)           <--- Note #1
Title                           : Forensics is fun
Creator                         : John
Last Modified By                : John
Revision Number                 : 2
Create Date                     : 2020:10:23 18:21:24Z
Modify Date                     : 2020:10:23 18:35:27Z
Total Edit Time                 : 4 minutes
Words                           : 7
Application                     : Microsoft Office PowerPoint
Presentation Format             : Widescreen
Paragraphs                      : 2
Slides                          : 58
Notes                           : 0
Hidden Slides                   : 1                              <---- Note #2
MM Clips                        : 0
Scale Crop                      : No
Heading Pairs                   : Fonts Used, 3, Theme, 1, Slide Titles, 58
Titles Of Parts                 : Arial, Calibri, Calibri Light, Office Theme, Forensics is fun, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation, PowerPoint Presentation
Links Up To Date                : No
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 16.0000
```

Here there are two noteworthy finds: an embedded preview image and one hidden slide.

Lets extract the preview image and view it with `eog`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ exiftool -b -PreviewImage Forensics_is_fun.pptm > preview.jpg 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ eog preview.jpg &
```

The preview image doesn't contain any flag though, just the text "Forensics is fun".

### Hunt for the hidden slide

The .pptm [file format](https://en.wikipedia.org/wiki/Office_Open_XML) is essentially a zip file that can be unpacked with `unzip`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ unzip Forensics_is_fun.pptm 
Archive:  Forensics_is_fun.pptm
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: ppt/presentation.xml    


  inflating: ppt/slides/_rels/slide46.xml.rels  
  inflating: ppt/slides/slide1.xml   
  inflating: ppt/slides/slide2.xml   
  inflating: ppt/slides/slide3.xml   
  inflating: ppt/slides/slide4.xml   
  inflating: ppt/slides/slide5.xml   
  inflating: ppt/slides/slide6.xml   
  inflating: ppt/slides/slide7.xml   
  inflating: ppt/slides/slide8.xml   
  inflating: ppt/slides/slide9.xml   
<---snip--->
  inflating: ppt/slideLayouts/slideLayout3.xml  
  inflating: ppt/slideLayouts/slideLayout4.xml  
  inflating: ppt/slideLayouts/slideLayout5.xml  
  inflating: ppt/slideLayouts/slideLayout6.xml  
  inflating: ppt/slideLayouts/slideLayout7.xml  
  inflating: ppt/slideLayouts/slideLayout8.xml  
  inflating: ppt/slideLayouts/slideLayout9.xml  
  inflating: ppt/slideLayouts/slideLayout10.xml  
  inflating: ppt/slideLayouts/slideLayout11.xml  
  inflating: ppt/slideMasters/_rels/slideMaster1.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout1.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout2.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout3.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout4.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout5.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout6.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout7.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout8.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout9.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout10.xml.rels  
  inflating: ppt/slideLayouts/_rels/slideLayout11.xml.rels  
  inflating: ppt/theme/theme1.xml    
 extracting: docProps/thumbnail.jpeg  
  inflating: ppt/vbaProject.bin      
  inflating: ppt/presProps.xml       
  inflating: ppt/viewProps.xml       
  inflating: ppt/tableStyles.xml     
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
  inflating: ppt/slideMasters/hidden  
```

Ah, the very last file called `hidden` looks very interesting.
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ file ppt/slideMasters/hidden 
ppt/slideMasters/hidden: ASCII text, with no line terminators

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ cat ppt/slideMasters/hidden
Z m x h Z z o g c G l j b 0 N U R n t E M W R f d V 9 r b j B 3 X 3 B w d H N f c l 9 6 M X A 1 f Q  
```

### Decode the flag

Hhm, apart from the spaces it almost looks like [Base64](https://en.wikipedia.org/wiki/Base64).

Lets try that
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Forensics/MacroHard_WeakEdge]
└─$ cat ppt/slideMasters/hidden | tr -d " " | base64 -d
flag: picoCTF{<REDACTED>}base64: invalid input
```

Probably some missing padding but we have the flag.

For additional information, please see the references below.

### References

- [Wikipedia - Macro (computer science)](https://en.wikipedia.org/wiki/Macro_(computer_science))
- [Wikipedia - Exif](https://en.wikipedia.org/wiki/Exif)
- [Wikipedia - Office Open XML](https://en.wikipedia.org/wiki/Office_Open_XML)
- [Wikipedia - Base64](https://en.wikipedia.org/wiki/Base64)
