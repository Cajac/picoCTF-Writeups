# WebDecode

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 50
Tags: picoCTF 2024, Web Exploitation, browser_webshell_solvable
Author: NANA AMA ATOMBO-SACKEY

Description:
Do you know how to use the web inspector?

Start searching here to find the flag

Hints:
1. Use the web inspector on other files included by the web page.
2. The flag may or may not be encoded
```
Challenge link: [https://play.picoctf.org/practice/challenge/427](https://play.picoctf.org/practice/challenge/427)

## Solution

### Manually investigate the web site

Browse to the web site and you will see a web page with the message "Ha!!!!!! You looking for a flag?".

On the page,  right-click and select 'View page source' (or press `CTRL + U`) to get the HTML-source of the page
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="style.css">
  <link rel="shortcut icon" href="img/favicon.png" type="image/x-icon">
  <!-- font (google) -->
  <link href="https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
  <title>Home</title>
</head>
<body>
<header>
  <nav>
    <div class="logo-container">
      <a href="index.html"><img src="img/binding_dark.gif" alt="logo"></a>
    </div>
    <div class="navigation-container">
      <ul>
        <li><a href="index.html">Home</a></li>
        <li><a href="about.html">About</a></li>
        <li><a href="contact.html">Contact</a></li>
      </ul>
    </div>
  </nav>
</header>
  <section class="banner">
    <h1>Ha!!!!!! You looking for a flag?</h1>
    <p>Keep Navigating</p>
  
  </section><!-- .banner -->
  <section class="sec-intro">
    <div class="col">
      <p>Haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</p>
      <p>Keepppppppppppppp Searchinggggggggggggggggggg</p>
      <img src="./img/multipage-html-img1.jpg" alt="person">
      <figcaption>Don't give up!</figcaption>
    </div>
  </section><!-- .sec-intro -->
  
  <footer>
    <div class="bottombar">Copyright © 2023 Your_Name. All rights reserved.</div>
  </footer>
  
</body>
</html>
```
Nope, nothing interesting here apart from several messages telling us to keep searching...

But there are more pages, like the `about.html` page which contains
```html
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="utf-8"/>
  <meta content="IE=edge" http-equiv="X-UA-Compatible"/>
  <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
  <link href="style.css" rel="stylesheet"/>
  <link href="img/favicon.png" rel="shortcut icon" type="image/x-icon"/>
  <!-- font (google) -->
  <link href="https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,400;0,700;1,400&amp;display=swap" rel="stylesheet"/>
  <title>
   About me
  </title>
 </head>
 <body>
  <header>
   <nav>
    <div class="logo-container">
     <a href="index.html">
      <img alt="logo" src="img/binding_dark.gif"/>
     </a>
    </div>
    <div class="navigation-container">
     <ul>
      <li>
       <a href="index.html">
        Home
       </a>
      </li>
      <li>
       <a href="about.html">
        About
       </a>
      </li>
      <li>
       <a href="contact.html">
        Contact
       </a>
      </li>
     </ul>
    </div>
   </nav>
  </header>
  <section class="about" notify_true="cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfMWY4MzI2MTV9">
   <h1>
    Try inspecting the page!! You might find it there
   </h1>
   <!-- .about-container -->
  </section>
  <!-- .about -->
  <section class="why">
   <footer>
    <div class="bottombar">
     Copyright © 2023 Your_Name. All rights reserved.
    </div>
   </footer>
  </section>
 </body>
</html>
```
The line `<section class="about" notify_true="cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfMWY4MzI2MTV9">` looks interesting.  
It seems to contain the flag in encoded form.

### Get the flag

There are no padding characters (`=`) at the end but the string looks like it could be [base64-encoded](https://en.wikipedia.org/wiki/Base64).  
We can decode it with the builtin linux tool `base64` like this
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2024/Web_Explotation/WebDecode]
└─$ echo "cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfMWY4MzI2MTV9" | base64 -d                     
picoCTF{<REDACTED>}  
```

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [Wikipedia - Base64](https://en.wikipedia.org/wiki/Base64)
- [Wikipedia - HTML](https://en.wikipedia.org/wiki/HTML)
