# who is it

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, Forensics, email
Author: JUNIAS BONOU

Description:
Someone just sent you an email claiming to be Google's co-founder Larry Page but you suspect a scam.

Can you help us identify whose mail server the email actually originated from?

Download the email file here. 
Flag: picoCTF{FirstnameLastname}

Hints:
1. whois can be helpful on IP addresses also, not only domain names.
```
Challenge link: [https://play.picoctf.org/practice/challenge/388](https://play.picoctf.org/practice/challenge/388)

## Solution

Let's start by opening the `email-export.eml` file in a text editor such as [Notepad++](https://notepad-plus-plus.org/).

If you are new to e-mail headers they can be a little bit confusing at first. Consider using one of the free online services as support.

Other wise, continue to the manual review below.

### Use an online service

Examples of online services that can help you analyze e-mail headers are:
 - [DNS Checker - Email Header Analyzer](https://dnschecker.org/email-header-analyzer.php)
 - [Google Admin - Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/)
 - [MXToolBox - Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)

### Manual review

Go through the e-mail header line by line until you start to find IPv4 addresses.

You will find the sender's IP-address in several headers such as the `Received` header
```
Received: from mail.onionmail.org (mail.onionmail.org. [173.249.33.206])
        by mx.google.com with ESMTPS id f16-20020a05600c4e9000b003a1947873d6si1882702wmq.224.2022.07.07.23.19.47
        for <francismanzi@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Jul 2022 23:19:47 -0700 (PDT)
```

and the `ARC-Authentication-Results` header
```
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@onionmail.org header.s=jan2022 header.b=4sU2nk5Z;
       spf=pass (google.com: domain of lpage@onionmail.org designates 173.249.33.206 as permitted sender) smtp.mailfrom=lpage@onionmail.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=onionmail.org
```

and the `Received-SPF` header
```
Received-SPF: pass (google.com: domain of lpage@onionmail.org designates 173.249.33.206 as permitted sender) client-ip=173.249.33.206;
```

So the sending IP-address is `173.249.33.206`.

### Whois lookup

Next, we need to lookup the registered owner of the IP-address with whois. 

This can be done with a linux tool such as `whois` or an online site such [DomainTools](https://whois.domaintools.com/173.249.33.206).

Let's use `whois` in this case
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/Forensics/who_is_it]
└─$ whois 173.249.33.206

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2023, American Registry for Internet Numbers, Ltd.
#


NetRange:       173.249.0.0 - 173.249.63.255
CIDR:           173.249.0.0/18
NetName:        RIPE
NetHandle:      NET-173-249-0-0-1
Parent:         NET173 (NET-173-0-0-0-0)
NetType:        Early Registrations, Transferred to RIPE NCC
OriginAS:       
Organization:   RIPE Network Coordination Centre (RIPE)
RegDate:        2017-09-14
Updated:        2017-09-14
Ref:            https://rdap.arin.net/registry/ip/173.249.0.0

ResourceLink:  https://apps.db.ripe.net/search/query.html
ResourceLink:  whois://whois.ripe.net

<--- snip --->

person:         Wilhelm Zwalina
address:        Contabo GmbH
address:        Aschauer Str. 32a
address:        81549 Muenchen
phone:          +49 89 21268372
fax-no:         +49 89 21665862
nic-hdl:        MH7476-RIPE
mnt-by:         MNT-CONTABO
mnt-by:         MNT-GIGA-HOSTING
created:        2010-01-04T10:41:37Z
last-modified:  2020-04-24T16:09:30Z
source:         RIPE

% Information related to '173.249.32.0/23AS51167'

route:          173.249.32.0/23
descr:          CONTABO
origin:         AS51167
mnt-by:         MNT-CONTABO
created:        2018-02-01T09:50:10Z
last-modified:  2018-02-01T09:50:10Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.107 (ABERDEEN)
```

You will find what/who you are looking for in the person record towards the end of the output.

For additional information, please see the references below.

## References

- [whois - Linux manual page](https://linux.die.net/man/1/whois)
