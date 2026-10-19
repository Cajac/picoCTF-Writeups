# Password Profiler

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
We intercepted a suspicious file from a system, but instead of the password itself, it only contains its SHA-1 hash. 
Using OSINT techniques, you are provided with personal details about the target. Your task is to leverage this 
information to generate a custom password list and recover the original password by matching its hash. 
Download the following files:

userinfo: Contains the personal details.
hash: Contains the SHA-1 hash of the password.
check_password: Script to test passwords against the hash.

Hints:
1. CUPP is a Python tool for generating custom wordlists from personal data.
```

Challenge link: [https://learn.cylabacademy.org/library/712](https://learn.cylabacademy.org/library/712)

## Solution

We start by checking out the given files:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ ls
check_password.py  hash.txt  userinfo.txt

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ cat check_password.py 
#!/usr/bin/env python3
import hashlib

HASH_FILE = "hash.txt"
WORDLIST_FILE = "passwords.txt" # wordlist that was generated using CUPP

def load_hash():
    with open(HASH_FILE, "r") as f:
        return f.read().strip()

def crack_password(target_hash):
    with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for password in f:
            password = password.strip()
            if hashlib.sha1(password.encode()).hexdigest() == target_hash:
                return password
    return None

if __name__ == "__main__":
    target_hash = load_hash()
    result = crack_password(target_hash)
    if result:
        print(f"Password found: academy{{{result}}}")
    else:
        print("No match found.")

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ cat hash.txt               
3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ cat userinfo.txt 
First Name: Alice
Surname: Johnson
Nickname: AJ
Birthdate: 15-07-1990
Partner's Name: Bob
Child's Name: Charlie
```

### Create a custom wordlist

Next, we create a custom wordlist with `cupp`. The wordlist should be called `passwords.txt`.

Install `cupp` with `sudo apt install cupp` if needed.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ cupp
/usr/bin/cupp:146: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("      \                     # User")
/usr/bin/cupp:147: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("       \   \033[1;31m,__,\033[1;m             # Passwords")
/usr/bin/cupp:148: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("        \  \033[1;31m(\033[1;moo\033[1;31m)____\033[1;m         # Profiler")
/usr/bin/cupp:149: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("           \033[1;31m(__)    )\ \033[1;m  ")
 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]

usage: cupp [-h] [-i | -w FILENAME | -l | -a | -v] [-q]

Common User Passwords Profiler

options:
  -h, --help         show this help message and exit
  -i, --interactive  Interactive questions for user password profiling
  -w FILENAME        Use this option to improve existing dictionary, or WyD.pl output to make some pwnsauce
  -l                 Download huge wordlists from repository
  -a                 Parse default usernames and passwords directly from Alecto DB. Project Alecto uses purified databases of Phenoelit and CIRT which were merged and enhanced
  -v, --version      Show the version of this program.
  -q, --quiet        Quiet mode (don't print banner)

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ cupp -i
/usr/bin/cupp:146: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("      \                     # User")
/usr/bin/cupp:147: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("       \   \033[1;31m,__,\033[1;m             # Passwords")
/usr/bin/cupp:148: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("        \  \033[1;31m(\033[1;moo\033[1;31m)____\033[1;m         # Profiler")
/usr/bin/cupp:149: SyntaxWarning: "\ " is an invalid escape sequence. Such sequences will not work in the future. Did you mean "\\ "? A raw string is also an option.
  print("           \033[1;31m(__)    )\ \033[1;m  ")
 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Alice
> Surname: Johnson
> Nickname: AJ
> Birthdate (DDMMYYYY): 15071990              


> Partners) name: Bob
> Partners) nickname: 
> Partners) birthdate (DDMMYYYY): 


> Child's name: Charlie
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 


> Pet's name: 
> Company name: 


> Do you want to add some key words about the victim? Y/[N]: N
> Do you want to add special chars at the end of words? Y/[N]: N
> Do you want to add some random numbers at the end of words? Y/[N]:N
> Leet mode? (i.e. leet = 1337) Y/[N]: N

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to alice.txt, counting 4558 words.
[+] Now load your pistolero with alice.txt and shoot! Good luck!

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ mv alice.txt passwords.txt
```

### Get the flag

Finally, we run the password checking script to get the flag:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ chmod +x check_password.py    

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Password_Profiler]
└─$ ./check_password.py                     
Password found: academy{<REDACTED>}
```

For additional information, please see the references below.

## References

- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [Cryptographic hash function - Wikipedia](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [CUPP - GitHub](https://github.com/Mebus/cupp)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [SHA-1 - Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
