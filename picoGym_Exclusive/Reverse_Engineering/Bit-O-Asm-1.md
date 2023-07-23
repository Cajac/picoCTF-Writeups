# Bit-O-Asm-1

- [Challenge information](Bit-O-Asm-1.md#challenge-information)
- [Solution](Bit-O-Asm-1.md#solution)
- [References](Bit-O-Asm-1.md#references)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, Reverse Engineering, X86_64
Author: LT 'SYREAL' JONES

Description:
Can you figure out what is in the eax register? 

Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base.  
If the answer was 0x11 your flag would be picoCTF{17}.

Hints:
1. As with most assembly, there is a lot of noise in the instruction dump.  
   Find the one line that pertains to this question and don't second guess yourself!
```

## Solution

Study the assembler listing to figure out what happens. The interesting line is prefixed with <+15>.  
For more information on the x64 instruction set, see references below.
```
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x4],edi
<+11>:    mov    QWORD PTR [rbp-0x10],rsi
<+15>:    mov    eax,0x30
<+20>:    pop    rbp
<+21>:    ret
```

The flag should be in decimal so convert it in Python:
```
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoGym/Reverse_Engineering/Bit-O-Asm-1]
└─$ python                                                             
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x30
48
```

Finally, create the flag like this `picoCTF{<Your_number>}`.

## References

Intel 64 and IA-32 Architectures Developer's Manuals in PDF-format  
- [Volume 2A: Instruction Set Reference, A-M](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
- [Volume 2B: Instruction Set Reference, M-U](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
- [Volume 2C: Instruction Set Reference, V-Z](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2c-manual.pdf)
