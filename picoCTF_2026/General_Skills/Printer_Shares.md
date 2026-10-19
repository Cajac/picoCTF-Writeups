# Printer Shares

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Easy
Tags: General Skills, picoCTF 2026
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Janice He

Description:
Oops! Someone accidentally sent an important file to a network printer—can you retrieve it from the print server?
The printer is on 13252.

you can try $ nc -vz chatelaine.cylabacademy.net 13252

Hints:
1. knowing how SMB protocol works would be helpful!
2. smbclient and smbutil are good tools
```

Challenge link: [https://learn.cylabacademy.org/library/759](https://learn.cylabacademy.org/library/759)

## Solution

We start by listing the available shares (`-L`) with `smbclient`:

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Printer_Shares]
└─$ smbclient -p 13252 -L chatelaine.cylabacademy.net -N

        Sharename       Type      Comment
        ---------       ----      -------
        shares          Disk      Public Share With Guests
        IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to chatelaine.cylabacademy.net failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

The `-N` specifies no password and prevents the command from prompting for one.

Next, we can connect to the `shares` share and list the files available. The `-U` parameter sets an empty username.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Printer_Shares]
└─$ smbclient -p 13252 -U '' //chatelaine.cylabacademy.net/shares -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep 23 09:02:23 2026
  ..                                  D        0  Wed Sep 23 09:02:23 2026
  dummy.txt                           N     1142  Wed Sep 23 02:59:21 2026
  flag.txt                            N       37  Wed Sep 23 09:02:23 2026

                65536 blocks of size 1024. 58696 blocks available
smb: \> 
```

We have two files including a `flag.txt` file.

### Get the flag

Let's download the flag file and view it locally.

```bash
smb: \> get flag.txt
getting file \flag.txt of size 37 as flag.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2026/General_Skills/Printer_Shares]
└─$ cat flag.txt     
academy{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
- [smbclient - Kali Tools](https://www.kali.org/tools/samba/#smbclient)
- [smbclient - Linux manual page](https://linux.die.net/man/1/smbclient)
