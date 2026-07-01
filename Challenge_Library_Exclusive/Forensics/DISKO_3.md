# DISKO 3

- [Challenge information](#challenge-information)
- [Static analysis solution](#static-analysis-solution)
- [Mount solution](#mount-solution)
- [References](#references)

## Challenge information

```text
Level: Medium
Points: 1
Tags: Challenge Library Exclusive, Forensics
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Darkraicg492

Description:
Can you find the flag in this disk image? This time, its not as plain as you think it is!

Download the disk image here.

Hints:
1. How will you search and extract files in a partition?
```

Challenge link: [https://learn.cylabacademy.org/library/507](https://learn.cylabacademy.org/library/507)

## Static analysis solution

### Unpacking and basic disk analysis

We start by unpacking the disk image and check the disk type

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ gzip -d disko-3.dd.gz 
gzip: disko-3.dd: Value too large for defined data type

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ file disko-3.dd    
disko-3.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "mkfs.fat", Media descriptor 0xf8, sectors/track 32, heads 8, sectors 204800 (volumes > 32 MB), FAT (32 bit), sectors/FAT 1576, serial number 0x49838d0b, unlabeled

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ fdisk -l disko-3.dd 
Disk disko-3.dd: 100 MiB, 104857600 bytes, 204800 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000
```

We have a disk with a MBR boot sector and a FAT32 file system.

### Check for files in the file system

We can check for files in the file system with the tool `fls` from TSK.  
With the `-r` parameter, we check recursively

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ fls disko-3.dd      
d/d 4:  log
v/v 3225859:    $MBR
v/v 3225860:    $FAT1
v/v 3225861:    $FAT2
V/V 3225862:    $OrphanFiles

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ fls -r disko-3.dd
d/d 4:  log
+ d/d 22:       private
+ d/d 24:       sysstat
+ d/d 26:       stunnel4
++ r/r 70:      stunnel.log
+ d/d 28:       mysql
+ d/d 30:       inetsim
++ d/d 102:     report
+ d/d 32:       installer
++ d/d 134:     cdebconf
+++ r/r 150:    questions.dat
+++ r/r 152:    templates.dat
++ r/r 136:     Xorg.0.log
++ r/r 138:     partman
++ r/r 140:     syslog
++ r/r 143:     hardware-summary
<---snip--->
```

There are a lot of files in the `log` directory so let's `grep` for files named `flag` only.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ fls -r disko-3.dd | grep -i flag
+ r/r 522628:   flag.gz
```

The flag file data starts at the meta data address 522628.

### Get the flag

We can extract the flag file with `icat` from TSK and then decompress it to get the flag in plaintext.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ icat disko-3.dd 522628 | gunzip 
Here is your flag
picoCTF{<REDACTED>}
```

## Mount solution

Alternatively, we can mount the FAT32 file system and examine the files in it.  
Create an empty directory to be used as mount point first if needed.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ sudo mount -o loop disko-3.dd /mnt/mount_pt 
[sudo] password for kali: 

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ cd /mnt/mount_pt                                                       

┌──(kali㉿kali)-[/mnt/mount_pt]
└─$ ls -l 
total 4
drwxr-xr-x 11 root root 3584 Mar 31  2025 log

┌──(kali㉿kali)-[/mnt/mount_pt]
└─$ cd log          

┌──(kali㉿kali)-[/mnt/mount_pt/log]
└─$ ls flag*
flag.gz
```

Then we can just the get the flag contents

```bash
┌──(kali㉿kali)-[/mnt/mount_pt/log]
└─$ gunzip --stdout flag.gz 
Here is your flag
picoCTF{<REDACTED>}
```

Finally, use `umount` to unmount the file system.

```bash
┌──(kali㉿kali)-[/mnt/mount_pt/log]
└─$ cd /mnt/hgfs/CTFs/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ sudo umount /mnt/mount_pt                  

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_3]
└─$ 
```

For additional information, please see the references below.

## References

- [dd - Linux manual page](https://man7.org/linux/man-pages/man1/dd.1.html)
- [fdisk - Linux manual page](https://linux.die.net/man/8/fdisk)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [File Allocation Table - Wikipedia](https://en.wikipedia.org/wiki/File_Allocation_Table)
- [File system - Wikipedia](https://en.wikipedia.org/wiki/File_system)
- [fls - The Sleuth Kit](https://wiki.sleuthkit.org/fls/)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [gunzip - Linux manual page](https://linux.die.net/man/1/gunzip)
- [gzip - Linux manual page](https://linux.die.net/man/1/gzip)
- [icat - The Sleuth Kit](https://wiki.sleuthkit.org/icat/)
- [Master boot record - Wikipedia](https://en.wikipedia.org/wiki/Master_boot_record)
- [mount - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [Partition type - Wikipedia](https://en.wikipedia.org/wiki/Partition_type)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [The Sleuth Kit - Tool Overview](https://wiki.sleuthkit.org/TSK-Tool-Overview/)
- [The Sleuth Kit - Commands](https://wiki.sleuthkit.org/The-Sleuth-Kit-commands/)
- [umount - Linux manual page](https://man7.org/linux/man-pages/man8/umount.8.html)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
