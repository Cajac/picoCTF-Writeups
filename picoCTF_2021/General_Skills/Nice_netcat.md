# Nice netcat...

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 15
Tags: picoCTF 2021, General Skills
Author: SYREAL

Description:
There is a nice program that you can talk to by using this command in a shell: 
$ nc mercury.picoctf.net 22902, but it doesn't speak English...

Hints:
1. You can practice using netcat with this picoGym problem: what's a netcat?
2. You can practice reading and writing ASCII with this picoGym problem: Let's Warm Up
```

## Solution

Below I offer two possible solutions: one manual with netcat and CyberChef and one fully automated with Python and pwntools.

### Solution #1 - netcat and CyberChef

LetsStart with connecting to the server with `nc`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/General_Skills/Nice_netcat]
└─$ nc mercury.picoctf.net 22902
112 
105 
99 
111 
67 
84 
70 
123 
103 
48 
48 
100 
95 
107 
49 
116 
116 
121 
33 
95 
110 
49 
99 
51 
95 
107 
49 
116 
116 
121 
33 
95 
100 
51 
100 
102 
100 
54 
100 
102 
125 
10 
```

Oh, a bunch of numbers...

Looking at the numbers we see that they are mainly numbers in the decimal range of 32-122, with the exception of the last 10.  
Therefore, they are most likely ASCII numbers.

To decode the flag we could use an online site such as [CyberChef](https://gchq.github.io/CyberChef/) and use the 'From Decimal' recipe. 

Enter 'decimal' in the `Operations` search bar, then drag and drop the `From Decimal` to the `Recipe`.  
Change the Delimiter to `Line feed`, copy the numbers to the `Input` pane and press `BAKE`.

The flag will be shown in the `Output` pane.

### Solution #2 - Python and pwntools

Alternatively, we can script everything with the help of [pwntools](https://docs.pwntools.com/en/stable/index.html)
```python
#!/usr/bin/python

from pwn import *

SERVER = 'mercury.picoctf.net'
PORT = 22902

io = remote(SERVER, PORT)    
numbers = io.recvallS()
num_str_array = numbers.split('\n')[:-1]
int_array = map(lambda x: int(x.strip()), num_str_array)
char_array = map(chr, int_array)
print(''.join(char_array))
io.close()
```

Then run the script to get the flag
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/General_Skills/Nice_netcat]
└─$ ~/python_venvs/pwntools/bin/python solve.py
[+] Opening connection to mercury.picoctf.net on port 22902: Done
[+] Receiving all data: Done (190B)
[*] Closed connection to mercury.picoctf.net port 22902
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Wikipredia - ASCII](https://en.wikipedia.org/wiki/ASCII)
- [ASCII Table](https://www.ascii-code.com/)
- [How the Python Lambda Function Works – Explained with Examples](https://www.freecodecamp.org/news/python-lambda-function-explained/)
