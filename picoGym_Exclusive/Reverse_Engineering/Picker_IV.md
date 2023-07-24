# Picker IV

- [Challenge information](Picker_IV.md#challenge-information)
- [Solution](Picker_IV.md#solution)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, Reverse Engineering
Author: LT 'SYREAL' JONES

Description:
Can you figure out how this program works to get the flag?

Connect to the program with netcat:
`$ nc saturn.picoctf.net 64448`

The program's source code can be downloaded here. The binary can be downloaded here.

Hints:
1. With Python, there are no binaries. With compiled languages like C, there is source code, and there are binaries.  
   Binaries are created from source code, they are a conversion from the human-readable source code, to the highly  
   efficient machine language, in this case: x86_64.
2. How can you find the address that win is at?
```

## Solution

### Study the source code

The `main` function of the program look like this
```c
int main() {
  signal(SIGSEGV, print_segf_message);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  unsigned int val;
  printf("Enter the address in hex to jump to, excluding '0x': ");
  scanf("%x", &val);
  printf("You input 0x%x\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

The input (variable val) is interpreted as a hex memory address and the function at that address is called.

And there is a `win` function that prints the flag which we are expected to call.
```c
int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}
```

Now, all we need to do is to find the address of the `win` function.

### Finding out the address of win

This can be done with `objdump` like this
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_IV]
└─$ objdump -t picker-IV | grep -i win
000000000040129e g     F .text  0000000000000096              win
```

Or with `gdb` and the -ex parameter to execute gdb commands like this
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_IV]
└─$ gdb -q -ex "info functions" -ex "quit" picker-IV | grep -i win
0x000000000040129e  win
```

### Write an exploit and try it locally

In this case our exploit is super easy. We just print the hex address and pipe it to the program
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_IV]
└─$ echo "40129e" | ./picker-IV
Enter the address in hex to jump to, excluding '0x': You input 0x40129e
You won!
Cannot open file.
```

Since there isn't any 'flag.txt' file in the current directory we get an error message, but otherwise it works.

### Connect to the server and get the flag

Finally, lets send our tiny exploit to the server
```
┌──(kali㉿kali)-[/picoCTF/picoGym/Reverse_Engineering/Picker_IV]
└─$ echo "40129e" | nc saturn.picoctf.net 64448
Enter the address in hex to jump to, excluding '0x': You input 0x40129e
You won!
picoCTF{<REDACTED>}
```
