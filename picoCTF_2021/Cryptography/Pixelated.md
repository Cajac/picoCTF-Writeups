# Pixelated

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2021, Cryptography
Author: SARA

Description:
I have these 2 images, can you make a flag out of them? 

scrambled1.png scrambled2.png

Hints:
1. https://en.wikipedia.org/wiki/Visual_cryptography
2. Think of different ways you can "stack" images
```

## Solution

There are several ways to solve this challenge and here are two of them.

### Stegsolve solution

You can use [StegSolve](https://github.com/Giotino/stegsolve) to combine the pictures. However, I never got the current 1.4 version to work and used the former [1.3 version](http://www.caesum.com/handbook/stego.htm) instead. 

In StegSolve 1.3, open the `scrambled1.png` file. Then, in the `Analyse`-menu select `Image Combiner` and select the `scrambled2.png` file. A new window opens where you can step through various ways to combine the images: XOR, OR, AND, ADD, SUB, etc.

You will find the flag with the `ADD`-method.

### Write a Python script

An alternative way to solve this challenge is to write a Python script with the help of the [Python Imaging Library - Pillow](https://pypi.org/project/Pillow/) and [numpy](https://pypi.org/project/numpy/)
```python
#!/usr/bin/python

from PIL import Image
from numpy import array

image1 = Image.open('scrambled1.png')
image2 = Image.open('scrambled2.png')

# Convert to arrays
array1 = array(image1)
array2 = array(image2)

# Combine/add the images
result = array1 + array2

# Save the result
Image.fromarray(result).save('flag.png')
print("Result saved as flag.png")
```

Then we run the script to combine the images
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Cryptography/Pixelated]
└─$ ~/python_venvs/Pillow/bin/python pixelaated.py
Result saved as flag.png
```

Finally, use `eog` or `feh` to view the `flag.png` image to get the flag.

For additional information, please see the references below.

## References

- [Wikipedia - Visual cryptography](https://en.wikipedia.org/wiki/Visual_cryptography)
