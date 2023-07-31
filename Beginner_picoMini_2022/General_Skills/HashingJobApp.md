# HashingJobApp

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: Beginner picoMini 2022, General Skills, hashing, nc, shell, Python
Author: LT 'SYREAL' JONES

Description:
If you want to hash with the best, beat this test!

nc saturn.picoctf.net 55823

Hints:
1. You can use a commandline tool or web app to hash text
2. Press Ctrl and c on your keyboard to close your connection and return to the command prompt.
```

## Solution

Connect to the server
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/HashingJobApp]
└─$ nc saturn.picoctf.net 55823
Please md5 hash the text between quotes, excluding the quotes: 'Greenpeace'
Answer: 
```

You are expected to hash the text. This can be done with an online service such as [Tools 4 noobs](https://www.tools4noobs.com/online_tools/hash/) or the tool `md5sum` as shown below.

Open a separate windows and run
```bash
└─$ echo -n 'Greenpeace' | md5sum                                                  
7628ecff54896cb076074261828e6623  -
```

Note that the `-n` parameter is important. This prevents a trailing newline (which is the default) to be added which will hash the hash.  
Copy the hash (the long hexadecimal number) and paste it in as the answer.

You need to be rather fast or otherwise the server disconnects you
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/HashingJobApp]
└─$ nc saturn.picoctf.net 55823
Please md5 hash the text between quotes, excluding the quotes: 'Helen Keller'
Answer: 
Time's up. Press Ctrl-C to disconnect. Feel free to reconnect and try again.
```

After you have been disconnected, new text will be randomly selected.

After three correct hashes are provided you get the flag.


For additional information, please see the references below.

### References

- [Wikipedia - MD5](https://en.wikipedia.org/wiki/MD5)
