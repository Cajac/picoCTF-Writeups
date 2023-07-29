# file-run2

- [Challenge information](file-run2.md#challenge-information)
- [Solution](file-run2.md#solution)
- [References](file-run2.md#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2022, Reverse Engineering
Author: WILL HONG
 
Description:
Another program, but this time, it seems to want some input. 
What happens if you try to run it on the command line with input "Hello!"?

Download the program here.
 
Hints:
1. Try running it and add the phrase "Hello!" with a space in front (i.e. "./run Hello!")
```

## Solution

Like the [previous challenge](file-run1.md) this challenge is really simple and the hint give it all away.
But lets play around with it anyway
```bash
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Reverse_Engineering/File_Run2]
└─$ chmod +x run
                                    
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Reverse_Engineering/File_Run2]
└─$ ./run
Run this file with only one argument.
                                                        
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Reverse_Engineering/File_Run2]
└─$ ./run My_argument
Won't you say 'Hello!' to me first?
                                                 
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Reverse_Engineering/File_Run2]
└─$ ./run Hello!     
The flag is: picoCTF{<REDACTED>}      
```

If you need more information, please see the references below.

## References

- [Linux path environment variable](https://linuxconfig.org/linux-path-environment-variable)
- [Linux file permissions explained](https://www.redhat.com/sysadmin/linux-file-permissions-explained)
- [Linux Commands and arguments](https://www.w3resource.com/linux-system-administration/commands-and-arguments.php)
