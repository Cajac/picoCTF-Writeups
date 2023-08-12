# Safe Opener 2

- [Challenge information](#challenge-information)
- [Solution](#solution)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, Reverse Engineering
Author: MUBARAK MIKAIL
 
Description:
What can you do with this file?

I forgot the key to my safe but this file is supposed to help me with retrieving the lost key.  
Can you help me unlock my safe?
 
Hints:
1. Download and try to decompile the file.
```

## Solution

There are several ways to solve this challenge. Here are two solutions presented in increasing difficulty.

### Solution #1 - Grepping for the flag

On easy challenges it's always recommended to search for the flag in plain text with `strings` and `grep`.
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/Reverse_Engineering/Safe_Opener_2]
└─$ strings -a -n 8 SafeOpener.class | grep picoCTF
,picoCTF{<REDACTED>}
```

### Solution #2 - Decompiling with JD-GUI

A more sofisticated solution is to decompile the file in [JD-GUI](https://github.com/java-decompiler/jd-gui) and study the code.

You find the flag in the openSafe function (but it's redacted here).
```C
  public static boolean openSafe(String password)
  {
    String encodedkey = "picoCTF{<REDACTED>}";
    if (password.equals(encodedkey))
    {
      System.out.println("Sesame open");
      return true;
    }
    System.out.println("Password is incorrect\n");
    return false;
  }
```
