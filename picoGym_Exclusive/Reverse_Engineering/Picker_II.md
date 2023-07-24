# Picker II

- [Challenge information](Picker_II.md#challenge-information)
- [Solution](Picker_II.md#solution)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, Reverse Engineering, Python
Author: LT 'SYREAL' JONES

Description:
Can you figure out how this program works to get the flag?

Connect to the program with netcat:
`$ nc saturn.picoctf.net 59461`

Hints:
 1. Can you do what win does with your input to the program?
```

## Solution

### Study the source code

Lets start by studying the "main" part of the python program.
```python
while(True):
  try:
    user_input = input('==> ')
    if( filter(user_input) ):
      eval(user_input + '()')
    else:
      print('Illegal input')
  except Exception as e:
    print(e)
```

The `filter` function is new and will make things somewhat harder for us
```python
def filter(user_input):
  if 'win' in user_input:
    return False
  return True
```

The `win` function is the same as in the previous 'Picker I' challenge
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

Lets try to call the `win` function directly
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_II]
└─$ nc saturn.picoctf.net 59461
==> win
Illegal input
==> Win
name 'Win' is not defined
```

### Get the flag

Finally, lets read the flag directly as suggested in the hint
```
==> print(open('flag.txt', 'r').read())
picoCTF{<REDACTED>}
'NoneType' object is not callable
==> 
```
