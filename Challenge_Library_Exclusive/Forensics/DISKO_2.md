# DISKO 2

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information

```text
Level: Medium
Points: 1
Tags: Challenge Library Exclusive, Forensics
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Author: Darkraicg492

Description:
Can you find the flag in this disk image? The right one is Linux! One wrong step and its all gone!

Download the disk image here.

Hints:
1. How can you extract/isolate a partition?
```

Challenge link: [https://learn.cylabacademy.org/library/506](https://learn.cylabacademy.org/library/506)

## Solution

### Unpacking and basic disk analysis

We start by unpacking the disk image and check the disk type

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ gzip -d disko-2.dd.gz 
gzip: disko-2.dd: Value too large for defined data type

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ file disko-2.dd 
disko-2.dd: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS (0x0,32,33), end-CHS (0x3,80,13), startsector 2048, 51200 sectors; partition 2 : ID=0xb, start-CHS (0x3,80,14), end-CHS (0x7,100,29), startsector 53248, 65536 sectors
```

Next, we want to examine the partition table. This can be done with either `mmls` from TSK or with `fdisk`.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ mmls disko-2.dd 
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000053247   0000051200   Linux (0x83)
003:  000:001   0000053248   0000118783   0000065536   Win95 FAT32 (0x0b)
004:  -------   0000118784   0000204799   0000086016   Unallocated

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ fdisk -l disko-2.dd               
Disk disko-2.dd: 100 MiB, 104857600 bytes, 204800 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x8ef8eaee

Device      Boot Start    End Sectors Size Id Type
disko-2.dd1       2048  53247   51200  25M 83 Linux
disko-2.dd2      53248 118783   65536  32M  b W95 FAT32
```

We have a disk with a MBR boot sector and two partitions: one Linux and one FAT32.

### Grep for the flag

If we try to just grep for the flag as in the [previous](DISKO_1.md) DISKO challenge, we get a lot of flags

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ strings -n 8 disko-2.dd | grep picoCTF | head
picoCTF{4_P4Rt_1t_i5_d3f931a0}
picoCTF{4_P4Rt_1t_i5_a3930df1}
picoCTF{4_P4Rt_1t_i5_f1d0a339}
picoCTF{4_P4Rt_1t_i5_fad03913}
picoCTF{4_P4Rt_1t_i5_139df3a0}
picoCTF{4_P4Rt_1t_i5_f931d3a0}
picoCTF{4_P4Rt_1t_i5_30da391f}
picoCTF{4_P4Rt_1t_i5_af33091d}
picoCTF{4_P4Rt_1t_i5_9d0331fa}
picoCTF{4_P4Rt_1t_i5_13a03f9d}

┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ strings -n 8 disko-2.dd | grep picoCTF | wc -l
126
```

We need to find the flag in the Linux partition (only).

### Get the flag

We can extract parts of the disk image with `dd` and then `grep` for strings in the Linux partition only to get the flag.

```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Challenge_Library_Exclusive/Forensics/DISKO_2]
└─$ dd if=disko-2.dd bs=512 skip=2048 count=51200 | strings -n 8 | grep picoCTF
picoCTF{<REDACTED>}
51200+0 records in
51200+0 records out
26214400 bytes (26 MB, 25 MiB) copied, 0.256569 s, 102 MB/s
```

For additional information, please see the references below.

## References

- [dd - Linux manual page](https://man7.org/linux/man-pages/man1/dd.1.html)
- [fdisk - Linux manual page](https://linux.die.net/man/8/fdisk)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [File Allocation Table - Wikipedia](https://en.wikipedia.org/wiki/File_Allocation_Table)
- [File system - Wikipedia](https://en.wikipedia.org/wiki/File_system)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [gzip - Linux manual page](https://linux.die.net/man/1/gzip)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [Master boot record - Wikipedia](https://en.wikipedia.org/wiki/Master_boot_record)
- [Mmls - The Sleuth Kit](https://wiki.sleuthkit.org/Mmls/)
- [Partition type - Wikipedia](https://en.wikipedia.org/wiki/Partition_type)
- [String (computer science) - Wikipedia](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [The Sleuth Kit - Tool Overview](https://wiki.sleuthkit.org/TSK-Tool-Overview/)
- [The Sleuth Kit - Commands](https://wiki.sleuthkit.org/The-Sleuth-Kit-commands/)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
