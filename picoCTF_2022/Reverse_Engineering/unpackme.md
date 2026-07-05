# unpackme

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Medium
Points: 300
Tags: picoCTF 2022, Reverse Engineering, binary, packed
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: LT 'SYREAL' JONES

Description:
Can you get the flag?

Reverse engineer this binary.
 
Hints:
1. What is UPX?
```

Challenge link: [https://learn.cylabacademy.org/library/313](https://learn.cylabacademy.org/library/313)

## Solution

### Basic file anaöysis

We start by analysing the given file

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ file unpackme-upx                         
unpackme-upx: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ strings -n 8 unpackme-upx                    
/@ _x/Ch#/P
AWAVAUATU
<---snip--->
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.95 Copyright (C) 1996-2018 the UPX Team. All Rights Reserved. $
/proc/self/exe
GCC: (Ubuntu 9.4.0-1u
<---snip--->
y%7-id`j
0Op! _O.v

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ 
```

We can confirm that the binary is [packed](https://en.wikipedia.org/wiki/Executable_compression) with [UPX](https://upx.github.io/).

### Unpack the binary

This packing is reversible and we can unpack the binary with `upx -d`.

The unpacking is done "in place" and the original file is overwritten unless we add `-o <file>` to unpack to a new file.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ upx -d -o unpacked unpackme-upx 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   1006445 <-    379188   37.68%   linux/amd64   unpacked

Unpacked 1 file.

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ file unpacked    
unpacked: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=b3d946c8b87ae1fd475e5dfbaa614d5f5b0006e9, for GNU/Linux 3.2.0, not stripped
```

### Grep for the flag

Before we do any more analysis, we should check if the flag is available in plaintext in the unpacked binary.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ strings -n 8 unpacked | grep picoCTF

```

Nope, not that easy.

### Do a test run of the binary

Let's also run the binary to learn more about it

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ ./unpacked 
What's my favorite number? 4711
Sorry, that's not it!
```

I guess the flag is printed if we select the right number.

### Decompile the binary in Ghidra

Now the reversing really starts and we decompile the binary in [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Import the file and analyze it with the default settings. Then double-click on the `main` function to show the decompiled version of it.

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  int local_44;
  char *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined2 local_1c;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0x4c75257240343a41;
  local_30 = 0x30623e306b6d4146;
  local_28 = 0x3532666630486637;
  local_20 = 0x36665f60;
  local_1c = 0x4e;
  printf("What\'s my favorite number? ");
  __isoc99_scanf(&DAT_004b3020,&local_44);
  if (local_44 == 0xb83cb) {
    local_40 = (char *)rotate_encrypt(0,&local_38);
    fputs(local_40,(FILE *)stdout);
    putchar(10);
    free(local_40);
  }
  else {
    puts("Sorry, that\'s not it!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We can see that if the numer is `0xb83cb` (which is decimal 754635) the flag is decoded and printed.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ python -c "print(0xb83cb)"        
754635
```

### Get the flag

Now that we know the favorite number, we run the binary again to get the flag

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2022/Reverse_Engineering/unpackme]
└─$ ./unpacked                
What's my favorite number? 754635
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Executable and Linkable Format - Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [Executable compression - Wikipedia](https://en.wikipedia.org/wiki/Executable_compression)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [Ghidra - GitHub](https://github.com/NationalSecurityAgency/ghidra)
- [Ghidra - Kali Tools](https://www.kali.org/tools/ghidra/)
- [Ghidra - Wikipedia](https://en.wikipedia.org/wiki/Ghidra)
- [String (computer science) - Wikipedia](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [UPX - Github](https://github.com/upx/upx)
- [upx - Linux manual page](https://linux.die.net/man/1/upx)
- [UPX - Homepage](https://upx.github.io/)
