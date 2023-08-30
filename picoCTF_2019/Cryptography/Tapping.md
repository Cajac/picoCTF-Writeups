# Tapping

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 200
Tags: picoCTF 2019, Cryptography
Author: DANNY

Description:
Theres tapping coming in from the wires. What's it saying 

nc jupiter.challenges.picoctf.org 21610.

Hints:
1. What kind of encoding uses dashes and dots?
2. The flag is in the format PICOCTF{}
```

## Solution

Tapping, dashes and dots - that ought to mean [morse code](https://en.wikipedia.org/wiki/Morse_code).

Lets connect to the server and find out
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/Cryptography/Tapping]
└─$ nc jupiter.challenges.picoctf.org 21610
.--. .. -.-. --- -.-. - ..-. { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. ...-- ----. ----- ..--- ----- .---- ----. ..... .---- ----. } 
```

Yes, that looks like morse code (apart from the curly braces).

To decode it we can use an online service such as the one from [onlineconversion](https://www.onlineconversion.com/morse_code.htm).

Copy and paste the output above to the lower part of the web site under `Convert morse code back into English`.  
Then press `Translate!` and the flag will be shown.

For additional information, please see the references below.

## References

- [Wikipedia - Morse code](https://en.wikipedia.org/wiki/Morse_code)
