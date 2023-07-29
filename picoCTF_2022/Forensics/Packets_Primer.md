# Packets Primer

- [Challenge information](Packets_Primer.md#challenge-information)
- [Solution](Packets_Primer.md#solution)
- [References](Packets_Primer.md#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2022, Forensics, pcap
Author: LT 'SYREAL' JONES

Description:
Download the packet capture file and use packet analysis software to find the flag.

Hints:
1. Wireshark, if you can install and use it, is probably the most beginner friendly packet analysis software product.
```

## Solution

Open up the PCAP-file in [Wireshark](https://www.wireshark.org/).

On easier challenges it can sometimes be worth searching for the flag i plaintext by entering a display filter of `tcp.payload contains "picoCTF"`. And it works here too. Packet number 4 matches and contains the flag. 

To construct/copy the flag you can either
 * See the packet's ASCII-details and construct the flag manually
 * Right-click on the 60-bytes of data and select Copy -> ...as Printable Text

For additional information, please see the references below.

## References

- [Wireshark display filter syntax and reference](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
