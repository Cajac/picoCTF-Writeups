# Bit-O-Asm-2

- [Challenge information](Bit-O-Asm-2.md#challenge-information)
- [Solution](Bit-O-Asm-2.md#solution)
- [References](Bit-O-Asm-2.md#references)

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
1. PTR's or 'pointers', reference a location in memory where values can be stored.
```

## Solution

Study the assembler listing to figure out what happens. The interesting line is prefixed with <+15>.  
The RBP register points to the current stack frame. For more information on the x64 instruction set, see references below.
```
<+0>:     endbr64 
<+4>:     push   rbp
<+5>:     mov    rbp,rsp
<+8>:     mov    DWORD PTR [rbp-0x14],edi
<+11>:    mov    QWORD PTR [rbp-0x20],rsi
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a
<+22>:    mov    eax,DWORD PTR [rbp-0x4]
<+25>:    pop    rbp
<+26>:    ret
```

The flag should be in decimal so convert it in Python:
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Bit-O-Asm-2]
└─$ python                                                             
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x9fe1a
654874
```

Finally, create the flag like this `picoCTF{<Your_number>}`.

## References

Intel 64 and IA-32 Architectures Developer's Manuals in PDF-format  
- [Volume 2A: Instruction Set Reference, A-M](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
- [Volume 2B: Instruction Set Reference, M-U](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
- [Volume 2C: Instruction Set Reference, V-Z](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2c-manual.pdf)
