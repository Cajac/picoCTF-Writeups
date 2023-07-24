# Picker III

- [Challenge information](Picker_III.md#challenge-information)
- [Solution](Picker_III.md#solution)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, Reverse Engineering, Python
Author: LT 'SYREAL' JONES

Description:
Can you figure out how this program works to get the flag?

Connect to the program with netcat:
`$ nc saturn.picoctf.net 60097`

Hints:
(None))
```

## Solution

### Study the source code

This time the python script is a bit larger. Lets start by looking at the "main" part
```python
import re

USER_ALIVE = True
FUNC_TABLE_SIZE = 4
FUNC_TABLE_ENTRY_SIZE = 32
CORRUPT_MESSAGE = 'Table corrupted. Try entering \'reset\' to fix it'

func_table = ''

<---function declation removed--->

reset_table()

while(USER_ALIVE):
  choice = input('==> ')
  if( choice == 'quit' or choice == 'exit' or choice == 'q' ):
    USER_ALIVE = False
  elif( choice == 'help' or choice == '?' ):
    help_text()
  elif( choice == 'reset' ):
    reset_table()
  elif( choice == '1' ):
    call_func(0)
  elif( choice == '2' ):
    call_func(1)
  elif( choice == '3' ):
    call_func(2)
  elif( choice == '4' ):
    call_func(3)
  else:
    print('Did not understand "'+choice+'" Have you tried "help"?')
```

One of the functions is the `win` function
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

However, the `win` function is not available in the function table
```python
def reset_table():
  global func_table

  # This table is formatted for easier viewing, but it is really one line
  func_table = \
'''\
print_table                     \
read_variable                   \
write_variable                  \
getRandomNumber                 \
'''
```

### Do a test run

Next lets explore the program behavior by running it as intended
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_III]
└─$ nc saturn.picoctf.net 60097
==> 1
1: print_table
2: read_variable
3: write_variable
4: getRandomNumber
==> 4
4
==> 2
Please enter variable name to read: func_table
print_table                     read_variable                   write_variable                  getRandomNumber                 
==> 
```

### Rewrite the function table to get the flag

Now, lets try to overwrite the function table
```
==> 3
Please enter variable name to write: func_table
Please enter new value of variable: "win   read_variable   write_variable   getRandomNumber"
==> 1
Table corrupted. Try entering 'reset' to fix it
==> reset
```

Hhm, that didn't work. We need to study the format of the function table in more detail.

Remember in global variables in the beginning of the script?
```python
FUNC_TABLE_SIZE = 4
FUNC_TABLE_ENTRY_SIZE = 32
CORRUPT_MESSAGE = 'Table corrupted. Try entering \'reset\' to fix it'
```

Also, see the `check_table` function
```python
def check_table():
  global func_table

  if( len(func_table) != FUNC_TABLE_ENTRY_SIZE * FUNC_TABLE_SIZE):
    return False

  return True
```

So the total length of the function table needs to be 32*4 = 128 bytes.

Create a 128-byte string with the letters 'win' left-aligned
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_III]
└─$ python -c "print('\"{0:<128}\"'.format('win'))" 
"win                                                                                                                             "
```

Then copy-paste this as input to the `func_table` variable
```
==> 3
Please enter variable name to write: func_table
Please enter new value of variable: "win                                                                                                                             "
==> 1
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x37 0x68 0x31 0x35 0x5f 0x31 0x35 0x5f 0x77 0x68 0x34 0x37 0x5f 0x77 0x33 0x5f 0x67 0x33 0x37 0x5f 0x77 0x31 0x37 0x68 0x5f 0x75 0x35 0x33 0x72 0x35 0x5f 0x31 0x6e 0x5f 0x63 0x68 0x34 0x72 0x67 0x33 0x5f 0x61 0x31 0x38 0x36 0x66 0x39 0x61 0x63 0x7d 
```

Finally, to get the plaintext flag you can use either [CyberChef](https://cyberchef.org/) or the `decode.py` script as in the  [Picker I challenge](Picker_I.md).
