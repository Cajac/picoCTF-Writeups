# Big Zip

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, General Skills
Author: LT 'SYREAL' JONES

Description:
Unzip this archive and find the flag.

Hints:
1. Can grep be instructed to look at every file in a directory and its subdirectories?
```
Challenge link: [https://play.picoctf.org/practice/challenge/322](https://play.picoctf.org/practice/challenge/322)

## Solution

Unzip the file
```
┌──(kali㉿kali)-[/picoCTF/picoGym/General_Skills/Big_Zip]
└─$ unzip big-zip-files.zip 
Archive:  big-zip-files.zip
   creating: big-zip-files/
 extracting: big-zip-files/jpvaawkrpno.txt  
  inflating: big-zip-files/oxbcyjsy.txt  
  inflating: big-zip-files/hllhxlvvdgiii.txt  
  inflating: big-zip-files/bdvnqbuutefealgveyiqd.txt  
  inflating: big-zip-files/fudfsewmaafsbniiyktzr.txt  
   creating: big-zip-files/folder_fqmjtuthge/
  inflating: big-zip-files/folder_fqmjtuthge/file_eaigogtrdslbxenbnfisxepj.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_ygocxgpzuxqjwfs.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_lqqprxhjtarithwygepdnlf.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_pdpygeaphbafepdzw.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_wwxeisxucykwqtkgcrkv.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_aowfebnypzsretakipi.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_jlfivzrgcubr.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_pnwvfhejwcqseezvmdv.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_lajnafrfzk.txt  
  inflating: big-zip-files/folder_fqmjtuthge/file_zqjgjdxgn.txt  
   creating: big-zip-files/folder_fqmjtuthge/folder_woanzvubrt/
 < ---snip--- >
```

The file listing is looong so we definetly needs to search for the flag with `grep`. Search  
 * recusively (-r), 
 * with extended regular expressions (-E), 
 * output only the matching text (-o), and 
 * suppress output of file names (-h).
```
┌──(kali㉿kali)-[/picoCTF/picoGym/General_Skills/Big_Zip]
└─$ grep -r -E -o -h 'picoCTF{.*}' big-zip-files
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [unzip - Linux manual page](https://linux.die.net/man/1/unzip)
