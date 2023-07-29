# Lookey here

- [Challenge information](Lookey_here.md#challenge-information)
- [Solution](Lookey_here.md#solution)

## Challenge information
```
Points: 100
Tags: picoCTF 2022, Forensics, grep
Author: LT 'SYREAL' JONES / MUBARAK MIKAIL
 
Description:
Attackers have hidden information in a very large mass of data in the past, maybe they are still doing it.

Download the data here.
 
Hints:
1. Download the file and search for the flag based on the known prefix.
```

## Solution

The most efficient way to get the flag is to use `grep` with `-o` to only output the matched text  
and `-E` to say that your pattern is an extended regular expression
```bash
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Forensics/Lookey_here]
└─$ grep -oE 'picoCTF{.*}' anthem.flag.txt
picoCTF{<REDACTED>}
```
