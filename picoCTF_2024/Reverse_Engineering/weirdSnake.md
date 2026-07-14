# weirdSnake

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Medium
Points: 300
Tags: picoCTF 2024, Reverse Engineering, Python, browser_webshell_solvable
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Junias Bonou
 
Description:
I have a friend that enjoys coding and he hasn't stopped talking about a snake recently

He left this file on my computer and dares me to uncover a secret phrase from it. Can you assist?
 
Hints:
1. Download and try to reverse the python bytecode.
2. https://docs.python.org/3/library/dis.html
```

Challenge link: [https://learn.cylabacademy.org/library/428](https://learn.cylabacademy.org/library/428)

## Solution

### Basic file analysis

We start with some basic analysis of the file

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2024/Reverse_Engineering/weirdSnake]
└─$ file snake              
snake: ASCII text

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2024/Reverse_Engineering/weirdSnake]
└─$ cat snake                                         
  1           0 LOAD_CONST               0 (4)
              2 LOAD_CONST               1 (54)
              4 LOAD_CONST               2 (41)
              6 LOAD_CONST               3 (0)
              8 LOAD_CONST               4 (112)
             10 LOAD_CONST               5 (32)
             12 LOAD_CONST               6 (25)
             14 LOAD_CONST               7 (49)
             16 LOAD_CONST               8 (33)
             18 LOAD_CONST               9 (3)
             20 LOAD_CONST               3 (0)
             22 LOAD_CONST               3 (0)
             24 LOAD_CONST              10 (57)
             26 LOAD_CONST               5 (32)
             28 LOAD_CONST              11 (108)
             30 LOAD_CONST              12 (23)
             32 LOAD_CONST              13 (48)
             34 LOAD_CONST               0 (4)
             36 LOAD_CONST              14 (9)
             38 LOAD_CONST              15 (70)
             40 LOAD_CONST              16 (7)
             42 LOAD_CONST              17 (110)
             44 LOAD_CONST              18 (36)
             46 LOAD_CONST              19 (8)
             48 LOAD_CONST              11 (108)
             50 LOAD_CONST              16 (7)
             52 LOAD_CONST               7 (49)
             54 LOAD_CONST              20 (10)
             56 LOAD_CONST               0 (4)
             58 LOAD_CONST              21 (86)
             60 LOAD_CONST              22 (43)
             62 LOAD_CONST              23 (105)
             64 LOAD_CONST              24 (114)
             66 LOAD_CONST              25 (91)
             68 LOAD_CONST               3 (0)
             70 LOAD_CONST              26 (71)
             72 LOAD_CONST              27 (106)
             74 LOAD_CONST              28 (124)
             76 LOAD_CONST              29 (93)
             78 LOAD_CONST              30 (78)
             80 BUILD_LIST              40
             82 STORE_NAME               0 (input_list)

  2          84 LOAD_CONST              31 ('J')
             86 STORE_NAME               1 (key_str)

  3          88 LOAD_CONST              32 ('_')
             90 LOAD_NAME                1 (key_str)
             92 BINARY_ADD
             94 STORE_NAME               1 (key_str)

  4          96 LOAD_NAME                1 (key_str)
             98 LOAD_CONST              33 ('o')
            100 BINARY_ADD
            102 STORE_NAME               1 (key_str)

  5         104 LOAD_NAME                1 (key_str)
            106 LOAD_CONST              34 ('3')
            108 BINARY_ADD
            110 STORE_NAME               1 (key_str)

  6         112 LOAD_CONST              35 ('t')
            114 LOAD_NAME                1 (key_str)
            116 BINARY_ADD
            118 STORE_NAME               1 (key_str)

  9         120 LOAD_CONST              36 (<code object <listcomp> at 0x7f0be3d36d40, file "snake.py", line 9>)
            122 LOAD_CONST              37 ('<listcomp>')
            124 MAKE_FUNCTION            0
            126 LOAD_NAME                1 (key_str)
            128 GET_ITER
            130 CALL_FUNCTION            1
            132 STORE_NAME               2 (key_list)

 11     >>  134 LOAD_NAME                3 (len)
            136 LOAD_NAME                2 (key_list)
            138 CALL_FUNCTION            1
            140 LOAD_NAME                3 (len)
            142 LOAD_NAME                0 (input_list)
            144 CALL_FUNCTION            1
            146 COMPARE_OP               0 (<)
            148 POP_JUMP_IF_FALSE      162

 12         150 LOAD_NAME                2 (key_list)
            152 LOAD_METHOD              4 (extend)
            154 LOAD_NAME                2 (key_list)
            156 CALL_METHOD              1
            158 POP_TOP
            160 JUMP_ABSOLUTE          134

 15     >>  162 LOAD_CONST              38 (<code object <listcomp> at 0x7f0be3d36df0, file "snake.py", line 15>)
            164 LOAD_CONST              37 ('<listcomp>')
            166 MAKE_FUNCTION            0
            168 LOAD_NAME                5 (zip)
            170 LOAD_NAME                0 (input_list)
            172 LOAD_NAME                2 (key_list)
            174 CALL_FUNCTION            2
            176 GET_ITER
            178 CALL_FUNCTION            1
            180 STORE_NAME               6 (result)

 18         182 LOAD_CONST              39 ('')
            184 LOAD_METHOD              7 (join)
            186 LOAD_NAME                8 (map)
            188 LOAD_NAME                9 (chr)
            190 LOAD_NAME                6 (result)
            192 CALL_FUNCTION            2
            194 CALL_METHOD              1
            196 STORE_NAME              10 (result_text)
            198 LOAD_CONST              40 (None)
            200 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f0be3d36d40, file "snake.py", line 9>:
  9           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                12 (to 18)
              6 STORE_FAST               1 (char)
              8 LOAD_GLOBAL              0 (ord)
             10 LOAD_FAST                1 (char)
             12 CALL_FUNCTION            1
             14 LIST_APPEND              2
             16 JUMP_ABSOLUTE            4
        >>   18 RETURN_VALUE

Disassembly of <code object <listcomp> at 0x7f0be3d36df0, file "snake.py", line 15>:
 15           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                16 (to 22)
              6 UNPACK_SEQUENCE          2
              8 STORE_FAST               1 (a)
             10 STORE_FAST               2 (b)
             12 LOAD_FAST                1 (a)
             14 LOAD_FAST                2 (b)
             16 BINARY_XOR
             18 LIST_APPEND              2
             20 JUMP_ABSOLUTE            4
        >>   22 RETURN_VALUE

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2024/Reverse_Engineering/weirdSnake]
└─$ 
```

Based on the challenge description this is likely the output of the Python [dis module](https://docs.python.org/3/library/dis.html).

### Overview of the output

First we need some overview of how we should read/interpret the output:

```text
  1           0 LOAD_CONST               0 (4)
              2 LOAD_CONST               1 (54)
```

From left to right we have:

- The first `1` on the first line is the **source code line number**
- The second number (`0` and `2`) is the **byte offsets** into the [bytecode](https://en.wikipedia.org/wiki/Bytecode)
- Then we have the **instruction**/**operation** (`LOAD_CONST`)

The rest of the values (operands) are specific to the instruction.

For [LOAD_CONST](https://docs.python.org/3/library/dis.html#opcode-LOAD_CONST) this is **offset** (**value**), i.e.

```python
input_list[0] = 4
input_list[1] = 54
```

The `>>` markers are **jump targets** and they mark loop tops/bottoms and branch destinations, which is a cue for while/for/if-statements.

### About Python bytecode

Python bytecode works on a [stack]((https://en.wikipedia.org/wiki/Stack_(abstract_data_type))) and the operations either *Pushes* (adds) or *Pops* (removes) things from the stack.

- Each `LOAD_*` pushes
- Each `BINARY_*`  and `CALL_*` pops operands and pushes a result
- Each `STORE_*` pops into a variable

### Build a Python script

I'm not aware of any tool(s) that "reverse" the above output back to Python code so I used a manual approach backup up by [Claude](https://claude.ai/) for some deep dives in the interpretation of the output.

#### Line 1

Line 1 corresponds to an `input_list` and is rather straight forward

```python
input_list = [4,54,41,0,112,32,25,49,33,3,0,0,57,32,108,23,48,4,9,70,7,110,36,8,108,7,49,10,4,86,43,105,114,91,0,71,106,124,93,78]
```

#### Line 2 - 6

Lines 2 through 6 sets the `key_str` variable.

```python
key_str = 'J'
key_str = '_' + key_str
key_str = key_str + 'o'
key_str = key_str + '3'
key_str = 't' + key_str
```

Note that characters are both prepended and appended!

We can summarize this as

```python
key_str == "t_Jo3"
```

#### Line 9

Here it gets tricker. To reconstruct line 9 we should look at both

```text
  9         120 LOAD_CONST              36 (<code object <listcomp> at 0x7f0be3d36d40, file "snake.py", line 9>)
            122 LOAD_CONST              37 ('<listcomp>')
<---snip--->
```

and

```text
Disassembly of <code object <listcomp> at 0x7f0be3d36d40, file "snake.py", line 9>:
  9           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
<---snip--->
```

Note the matching line numbers and hexadecimal address.

The corresponding Python code is

```python
key_list = [ord(char) for char in key_str]
```

#### Line 11 and 12

These lines is a bit easier than line 9 and corresponds to a `while`-statement.

Note the destination bytecode offset of the lines

```text
            160 JUMP_ABSOLUTE          134
```

and

```text
            148 POP_JUMP_IF_FALSE      162
```

This corresponds to this code

```python
while len(key_list) < len(input_list):
    key_list.extend(key_list)
```

#### Line 15

Another tricky one were we need to take two sections into account.

This corresponds to

```python
result = [a ^ b for a, b in zip(input_list, key_list)]
```

#### Line 18

Finally, we have line 18 that corresponds to

```python
result_text = ''.join(map(chr, result))
```

### The total script

In total we have this script, were I have also added a statement to print the flag at the end and a shebang at the beginning.

```python
#!/usr/bin/python3

input_list = [4,54,41,0,112,32,25,49,33,3,0,0,57,32,108,23,48,4,9,70,7,110,36,8,108,7,49,10,4,86,43,105,114,91,0,71,106,124,93,78]

key_str = "t_Jo3"

key_list = [ord(char) for char in key_str]

while len(key_list) < len(input_list):
    key_list.extend(key_list)

result = [a ^ b for a, b in zip(input_list, key_list)]

result_text = ''.join(map(chr, result))

print(result_text)
```

### Get the flag

Now all we have to do is run the script to get the flag

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2024/Reverse_Engineering/weirdSnake]
└─$ ./script.py
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Bytecode - Wikipedia](https://en.wikipedia.org/wiki/Bytecode)
- [dis module - Python](https://docs.python.org/3/library/dis.html)
- [join - string method - Python Docs](https://docs.python.org/3/library/stdtypes.html#str.join)
- [List Comprehensions - Python Docs](https://docs.python.org/3/tutorial/datastructures.html#list-comprehensions)
- [map function - Python Docs](https://docs.python.org/3/library/functions.html#map)
- [ord function - Python Docs](https://docs.python.org/3.4/library/functions.html#ord)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [Shebang (Unix) - Wikipedia](https://en.wikipedia.org/wiki/Shebang_(Unix))
- [Stack (abstract data type) - Wikipedia](https://en.wikipedia.org/wiki/Stack_(abstract_data_type))
- [zip function - Python Docs](https://docs.python.org/3.4/library/functions.html#zip)
- [XOR cipher - Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
