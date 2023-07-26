# PcapPoisoning

- [Challenge information](PcapPoisoning.md#challenge-information)
- [Solution](PcapPoisoning.md#solution)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, Forensics, pcap
Author: MUBARAK MIKAIL

Description:
How about some hide and seek heh?
Download this file and find the flag.

Hints:
(None)
```

## Solution

Open the PCAP-file in [Wireshark](https://www.wireshark.org/) and lets take the description more or less literally by just assuming the flag are available in plain in the packet capture.

Set a display filter of `tcp.payload contains "picoCTF"` and press Enter.

Ah, only one packet matches and the flag is indeed visible in the ASCII details of the packet.
