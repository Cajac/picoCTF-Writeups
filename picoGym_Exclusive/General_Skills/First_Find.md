# First Find

- [Challenge information](First_Find.md#challenge-information)
- [Solution](First_Find.md#solution)

## Challenge information
```
Points: 100
Tags: picoGym Exclusive, General Skills
Author: LT 'SYREAL' JONES

Description:
Unzip this archive and find the file named 'uber-secret.txt'

Hints:
(None)
```

## Solution

Unzip the file
```
┌──(kali㉿kali)-[/picoCTF/picoGym/General_Skills/Fist_Find]
└─$ unzip files.zip 
Archive:  files.zip
   creating: files/
   creating: files/satisfactory_books/
   creating: files/satisfactory_books/more_books/
  inflating: files/satisfactory_books/more_books/37121.txt.utf-8  
  inflating: files/satisfactory_books/23765.txt.utf-8  
  inflating: files/satisfactory_books/16021.txt.utf-8  
  inflating: files/13771.txt.utf-8   
   creating: files/adequate_books/
   creating: files/adequate_books/more_books/
   creating: files/adequate_books/more_books/.secret/
   creating: files/adequate_books/more_books/.secret/deeper_secrets/
   creating: files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/
 extracting: files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt  
  inflating: files/adequate_books/more_books/1023.txt.utf-8  
  inflating: files/adequate_books/46804-0.txt  
  inflating: files/adequate_books/44578.txt.utf-8  
   creating: files/acceptable_books/
   creating: files/acceptable_books/more_books/
  inflating: files/acceptable_books/more_books/40723.txt.utf-8  
  inflating: files/acceptable_books/17880.txt.utf-8  
  inflating: files/acceptable_books/17879.txt.utf-8  
  inflating: files/14789.txt.utf-8   
```

The path to the file is visible in the middle of the file listing (prefixed with extracting) but lets search for it anyway
```
┌──(kali㉿kali)-[/picoCTF/picoGym/General_Skills/Fist_Find]
└─$ find files -name uber-secret.txt
files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt
```

Finally, display the flag with cat
```
┌──(kali㉿kali)-[/picoCTF/picoGym/General_Skills/Fist_Find]
└─$ cat files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt
picoCTF{<REDACTED>}
```
