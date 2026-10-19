# bytemancy 0

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Tags: General Skills, picoCTF 2026
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: LT 'syreal' Jones

Description:
Can you conjure the right bytes? The program's source code can be downloaded here.

Connect to the program with netcat:

$ nc xebec.cylabacademy.net 17808

Hints:
1. Solving this with a one-liner will help with the next challenge in this series
```

Challenge link: [https://learn.cylabacademy.org/library/742](https://learn.cylabacademy.org/library/742)

## Solution

We start by checking out the Python source code:

```python
while(True):
  try:
    print('⊹──────[ BYTEMANCY-0 ]──────⊹')
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print()
    print('Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space.')
    print()
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print('⊹─────────────⟡─────────────⊹')
    user_input = input('==> ')
    if user_input == "\x65\x65\x65":
      print(open("./flag.txt", "r").read())
      break
    else:
      print("That wasn't it. I got: " + str(user_input))
      print()
      print()
      print()
  except Exception as e:
    print(e)
    break
```

We are expected to send the ASCII decimal value `101` three times to get the flag.

ASCII decimal 101 corresponds to a lower-case `e`:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/bytemancy_1]
└─$ python -c 'print(chr(101))'    
e
```

We can also see that decimal 101 corresponds to hexadecimal value 0x65.

### Get the flag

We can get the flag with Python:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/bytemancy_0]
└─$ python -c 'print(chr(101) * 3)' | nc xebec.cylabacademy.net 17808
⊹──────[ BYTEMANCY-0 ]──────⊹
☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐

Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space.

☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐
⊹─────────────⟡─────────────⊹
==> academy{<REDACTED>}
```

Or with `echo` using the hexadecimal values:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/bytemancy_0]
└─$ echo -e '\x65\x65\x65' | nc xebec.cylabacademy.net 17808
⊹──────[ BYTEMANCY-0 ]──────⊹
☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐

Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space.

☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐
⊹─────────────⟡─────────────⊹
==> academy{<REDACTED>}
```

Or finally with `echo` using the ASCII-values, i.e. the letter `e`:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/bytemancy_0]
└─$ echo 'eee' | nc xebec.cylabacademy.net 17808
⊹──────[ BYTEMANCY-0 ]──────⊹
☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐

Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space.

☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐
⊹─────────────⟡─────────────⊹
==> academy{<REDACTED>}
```

For additional information, please see the references below.

## References

- [ASCII - Wikipedia](https://en.wikipedia.org/wiki/ASCII)
- [chr function - Python Docs](https://docs.python.org/3/library/functions.html#chr)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [python - Linux manual page](https://linux.die.net/man/1/python)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
