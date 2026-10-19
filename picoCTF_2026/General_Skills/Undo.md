# Undo

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Tags: General Skills, picoCTF 2026
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Yahaya Meddy

Description:
Can you reverse a series of Linux text transformations to recover the original flag?
Start searching for the flag here nc xebec.cylabacademy.net 26636

Hints:
1. For text translation and character replacement, see tr command documentation.
```

Challenge link: [https://learn.cylabacademy.org/library/766](https://learn.cylabacademy.org/library/766)

## Solution

We start by connecting with netcat:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Undo]
└─$ nc xebec.cylabacademy.net 26636
===Welcome to the Text Transformations Challenge!===

Your goal: step by step, recover the original flag.
At each step, you'll see the transformed flag and a hint.
Enter the correct Linux command to reverse the last transformation.

--- Step 1 ---
Current flag: KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu
Hint: Base64 encoded the string.
Enter the Linux command to reverse it:
```

We are tasked to find the reverse operations a number of times. Just the part with the reverse command and its parameters and not the **full** command as shown below.

```bash
--- Step 1 ---
Current flag: KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu
Hint: Base64 encoded the string.
Enter the Linux command to reverse it: echo 'KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu' | base64 -d
Incorrect. Try again.
Output: [Error] Command not allowed.
Hint: Try reversing: base64

Enter the Linux command to reverse it: base64 -d
Correct!
```

### Get the flag

The commands we should use are `rev` and `tr` until we get the flag.

```bash
--- Step 2 ---
Current flag: )pp08q77p-fa01g@ze0sfa4eG-gk3g-ta1ferirE(lzrqnpn
Hint: Reversed the text.
Enter the Linux command to reverse it: rev
Correct!

--- Step 3 ---
Current flag: npnqrzl(Eriref1at-g3kg-Ge4afs0ez@g10af-p77q80pp)
Hint: Replaced underscores with dashes.
Enter the Linux command to reverse it: tr - _
Correct!

--- Step 4 ---
Current flag: npnqrzl(Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp)
Hint: Replaced curly braces with parentheses.
Enter the Linux command to reverse it: tr '()' '{}'
Correct!

--- Step 5 ---
Current flag: npnqrzl{Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp}
Hint: Applied ROT13 to letters.
Enter the Linux command to reverse it: tr 'A-Za-z' 'N-ZA-Mn-za-m'
Correct!

Congratulations! You've recovered the original flag:
>>> academy{<REDACTED>}
```

The above is the guided mode version of what we also can do manually like this:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Undo]
└─$ echo 'KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu' | base64 -d
)pp08q77p-fa01g@ze0sfa4eG-gk3g-ta1ferirE(lzrqnpn 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Undo]
└─$ echo 'KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu' | base64 -d | rev
npnqrzl(Eriref1at-g3kg-Ge4afs0ez@g10af-p77q80pp) 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Undo]
└─$ echo 'KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu' | base64 -d | rev | tr - _
npnqrzl(Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp) 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Undo]
└─$ echo 'KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu' | base64 -d | rev | tr - _ | tr '()' '{}'
npnqrzl{Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp} 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Undo]
└─$ echo 'KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu' | base64 -d | rev | tr - _ | tr '()' '{}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
academy{<REDACTED>}
```

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [rev - Linux manual page](https://man7.org/linux/man-pages/man1/rev.1.html)
- [ROT13 - Wikipedia](https://en.wikipedia.org/wiki/ROT13)
- [tr - Linux manual page](https://man7.org/linux/man-pages/man1/tr.1.html)
