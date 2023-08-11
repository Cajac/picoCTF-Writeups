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

### Connect to the server

Lets connect to the server with `nc` as instructed
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

### Decode the flag

To decode the flag we could use an online site such as [CyberChef](https://gchq.github.io/CyberChef/) and use the 'From Decimal' recipe. 

Enter 'decimal' in the `Operations` search bar, then drag and drop the `From Decimal` to the `Recipe`.  
Change the Delimiter to `Line feed`, copy the numbers to the `Input` pane and press `BAKE`.

The flag will be shown in the `Output` pane.

### References

- [Wikipredia - ASCII](https://en.wikipedia.org/wiki/ASCII)
- [ASCII Table](https://www.ascii-code.com/)
