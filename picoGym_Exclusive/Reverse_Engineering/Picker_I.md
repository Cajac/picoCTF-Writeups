# Picker I

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, Reverse Engineering, Python
Author: LT 'SYREAL' JONES

Description:
This service can provide you with a random number, but can it do anything else?

Connect to the program with netcat:
`$ nc saturn.picoctf.net 58059`

Hints:
 1. Can you point the program to a function that does something useful for you?
```

## Solution

### Study the source code

Lets start by studying the "main" part of the python program.
```python
while(True):
  try:
    print('Try entering "getRandomNumber" without the double quotes...')
    user_input = input('==> ')
    eval(user_input + '()')
  except Exception as e:
    print(e)
```

Then check the `getRandomNumber` function
```python
def getRandomNumber():
  print(4)  # Chosen by fair die roll.
            # Guaranteed to be random.
            # (See XKCD)
```
The comment is referring to this [XKCD comic strip](https://xkcd.com/221/).

More interesting is this `win` function which output the flag as hex values.
```python
def win():
  # This line will not work locally unless you create your own 'flag.txt' in
  #   the same directory as this script
  flag = open('flag.txt', 'r').read()
  #flag = flag[:-1]
  flag = flag.strip()
  str_flag = ''
  for c in flag:
    str_flag += str(hex(ord(c))) + ' '
  print(str_flag)
```

### Do a test run

Next lets explore the program behavior by running it
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_I]
└─$ nc saturn.picoctf.net 58059
Try entering "getRandomNumber" without the double quotes...
==> getRandomNumber
4
```

### Get the encoded flag

Now lets call the `win` function instead to get the flag
```
Try entering "getRandomNumber" without the double quotes...
==> win
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x36 0x65 0x30 0x34 0x34 0x34 0x30 0x64 0x7d 
```

### Get the plaintext flag

Finally, we need to decode the flag. This can be done with [CyberChef's 'From Hex' recipe](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')) or with a python script.

Lets write a python script called `decode.py`
```python
#!/usr/bin/python

# Create an array of the hex string numbers
enc_flag_array = "0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x36 0x65 0x30 0x34 0x34 0x34 0x30 0x64 0x7d ".split()

# Convert to numbers
num_array = map(lambda x: int(x, 16), enc_flag_array)

# Convert to chars
char_array = map(chr, num_array)

# Join and print the flag
print(''.join(char_array))
```

Then set the script file as executable and run it to get the flag
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_I]
└─$ chmod a+x decode.py                                           

┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_I]
└─$ ./decode.py   
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [ASCII Table](https://www.asciitable.com/)
- [chr function - Python](https://docs.python.org/3/library/functions.html#chr)
- [CyberChef - Homepage](https://gchq.github.io/CyberChef/)
- [join method - Python](https://docs.python.org/3/library/stdtypes.html#str.join)
- [lambda expression - Python](https://docs.python.org/3/reference/expressions.html#lambda)
- [map function - Python](https://docs.python.org/3/library/functions.html#map)
- [Wikipedia - ASCII](https://en.wikipedia.org/wiki/ASCII)
