# keygenme-py

- [Challenge information](#challenge-information)
- [Solutions](#solutions)
- [References](#references)

## Challenge information
```
Points: 30
Tags: picoCTF 2021, Reverse Engineering
Author: SYREAL

Description:

keygenme-trial.py

Hints:
(None)
```

## Solutions

### Analyze the Python script

Lets start by looking at the beginning of the script
```python
#============================================================================#
#============================ARCANE CALCULATOR===============================#
#============================================================================#

import hashlib
from cryptography.fernet import Fernet
import base64

# GLOBALS --v
arcane_loop_trial = True
jump_into_full = False
full_version_code = ""

username_trial = "GOUGH"
bUsername_trial = b"GOUGH"

key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial

<---snip--->
```

There we have what seems to be most parts of the flag, apart from a unknown dymanic part.

Further down we have a menu function called `menu_trial`
```python
def menu_trial():
    print("___Arcane Calculator___\n\n\
Menu:\n\
(a) Estimate Astral Projection Mana Burn\n\
(b) [LOCKED] Estimate Astral Slingshot Approach Vector\n\
(c) Enter License Key\n\
(d) Exit Arcane Calculator")

    choice = input("What would you like to do, "+ username_trial +" (a/b/c/d)? ")
    
    if not validate_choice(choice):
        print("\n\nInvalid choice!\n\n")
        return
    
    if choice == "a":
        estimate_burn()
    elif choice == "b":
        locked_estimate_vector()
    elif choice == "c":
        enter_license()
    elif choice == "d":
        global arcane_loop_trial
        arcane_loop_trial = False
        print("Bye!")
    else:
        print("That choice is not valid. Please enter a single, valid \
lowercase letter choice (a/b/c/d).")
```

Lets check the `enter_license` function next
```python
def enter_license():
    user_key = input("\nEnter your license key: ")
    user_key = user_key.strip()

    global bUsername_trial
    
    if check_key(user_key, bUsername_trial):
        decrypt_full_version(user_key)
    else:
        print("\nKey is NOT VALID. Check your data entry.\n\n")
```

It calls the `check_key` function so lets investigate that
```python
def check_key(key, username_trial):

    global key_full_template_trial

    if len(key) != len(key_full_template_trial):
        return False
    else:
        # Check static base key part --v
        i = 0
        for c in key_part_static1_trial:
            if key[i] != c:
                return False
            i += 1

        # TODO : test performance on toolbox container
        # Check dynamic part --v
        if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[5]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[3]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[6]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[2]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[7]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[1]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[8]:
            return False

        return True
```

Ah, here we have the dynamic part. It checks a number of hash digits, in some strange order, of the trial user name.

### Get the flag

Lets make a small script to compile the complete flag
```python
#!/usr/bin/python

import hashlib

# Static parts
key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_static2_trial = "}"

# Dynamic part - same as in the check_key function
bUsername_trial = b"GOUGH"
hash = hashlib.sha256(bUsername_trial).hexdigest()
dynamic = hash[4] + hash[5] + hash[3] + hash[6] + hash[2] + hash[7] + hash[1] + hash[8]

flag = "picoCTF{1n_7h3_|<3y_of_" + dynamic + "}"
print(flag)
```

Then, make sure the script is executable and run it to get the flag
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Reverse_Engineering/keygenme-py]
└─$ chmod +x solve.py 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Reverse_Engineering/keygenme-py]
└─$ ./solve.py
picoCTF{<REDACTED>}
```

## References

- [hashlib — Secure hashes and message digests](https://docs.python.org/3/library/hashlib.html)
