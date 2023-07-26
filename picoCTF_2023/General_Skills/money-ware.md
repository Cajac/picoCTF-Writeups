# money-ware

- [Challenge information](money-ware.md#challenge-information)
- [Solution](money-ware.md#solution)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, General Skills, osint
Author: JUNI19
  
Description:
Flag format: picoCTF{Malwarename}
The first letter of the malware name should be capitalized and the rest lowercase.

Your friend just got hacked and has been asked to pay some bitcoins to 1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX.  
He doesn’t seem to understand what is going on and asks you for advice.  
Can you identify what malware he’s being a victim of?

Hints:
1. Some crypto-currencies abuse databases exist; check them out!
2. Maybe Google might help.
```

## Solution

Lets start easy and just Google for the Bitcoin address `1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX`.

Looking through the top search results you can see headlines such as
 * [Petya Ransomware Fast Spreading Attack](https://otx.alienvault.com/pulse/59525e7a95270e240c055ead/)
 * [The Petya ransomware attack made $20k less than ...](https://qz.com/1016525/the-petya-ransomware-cyberattack-has-earned-hackers-20k-less-than-wannacry-in-its-first-24-hours)

So maybe 'Petya' is the malware we are looking for and indeed it is...
 
