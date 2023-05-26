---
title: "Kraken - The Deep Sea Lurker Part 2"
classes: wide
header:
  teaser: /assets/images/Kraken-Keylogger-pt2/logo.png
  overlay_image: /assets/images/Kraken-Keylogger-pt2/logo.png
  overlay_filter: 0.5
ribbon: Crimson
excerpt: "Part 2 of analyzing the KrakenKeylogger Malware"
description: "Part 2 of analyzing the KrakenKeylogger Malware"
categories:
  - Threat Hunting
tags:
  - KrakenKeylogger
  - Dorking
  - URLscan
  - VirusTotal
  - URLhaus
  - UnpackMe
  - Yara
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
---

# Intro

In the second part of analyzing the "KrakenKeylogger", I will be diving into some proactive "threat hunting" steps I've done during my research about the Kraken. <br>
If you haven't already read the first part of analyzing the Kraken, be sure to check it out [here](https://0xtoxin.github.io/malware%20analysis/KrakenKeylogger-pt1/) <br>
With that saying let's begin!

# What we have?

Let's start with what we currently have and how can we pivot with it:
- **C2:** thereccorp.com
- **Payload fetching domain:** masherofmasters.cyou
- **Binary Name:** KrakenStub

The hunting will be splitted into 4 part:
1. thereccorp.com analysis 
2. masherofmasters.cyou analysis
3. UnpackMe Yara Hunt
4. OSINT research

# thereccorp.com Analysis 

We start off with our final C2 domain `thereccorp.com`, searching the domain in [VirusTotal](https://www.virustotal.com/gui/domain/thereccorp.com/detection) will respond us with a solid **0/87** vendors detection:

![image.png](/assets/images/Kraken-Keylogger-pt2/1.png)

going to the `relations` tab and looking at the `Communicating Files` files we can see 22 files which all were flagged as malicious:

![image-2.png](/assets/images/Kraken-Keylogger-pt2/2.png)

all files are pretty recent (oldest one dated to `7th of May 23`), this in fact helps us to understand that the campaign is pretty new and keeps being distributed. <br>

Some files were already analyzed by various sandboxes and this helped me a lot by downloading the file from those sandboxes reports (most Sandboxes I know allow downloading the examined sample).
Let's have a look at couple samples that were actually flagged falsely

## RareCommodityHelper.exe

- Sha256: 8a6bebf08f6c223ed9821ee3b80e420060c66770402687f5c98555f9b0cd02a3
- [VirusTotal](https://www.virustotal.com/gui/file/8a6bebf08f6c223ed9821ee3b80e420060c66770402687f5c98555f9b0cd02a3/detection)
- [MalwareBazaar](https://bazaar.abuse.ch/sample/8a6bebf08f6c223ed9821ee3b80e420060c66770402687f5c98555f9b0cd02a3/)

Looking at the `Vendor Threat Intelligence` tab in the MalwareBazaar report we can see that 3 different family associated with the sample.

![image-3.png](/assets/images/Kraken-Keylogger-pt2/3.png)

I've opened the report of [JoeSandBox](https://www.joesandbox.com/analysis/863303/0/html) and simply searched for the string `kraken` and surprisingly look what popped up:

![image-4.png](/assets/images/Kraken-Keylogger-pt2/4.png)

Why would `AgentTesla` malware will have `KrakenStub` named file during it's execution? 

I took a look also [UnpackMe](https://www.unpac.me/results/dd258f66-c163-4254-810c-4ee8e3c0b643/#/) report. <br>
Looking at the Unpacked binary that was flagged as `masslogger` we can see the `ProductName`, `FileDescription`, `OriginalFilename` and `InternalName` share the same suspicious string we're looking for: `KrakenStub`

![image-5.png](/assets/images/Kraken-Keylogger-pt2/5.png)

## RareCommodityHelper.exe
- Sha256: 413ec94d35627af97c57c6482630e6b2bb299eebf164e187ea7df0a0eb80ecc6
- [VirusTotal](https://www.virustotal.com/gui/file/413ec94d35627af97c57c6482630e6b2bb299eebf164e187ea7df0a0eb80ecc6/community)
- [MalwareBazaar](https://bazaar.abuse.ch/sample/413ec94d35627af97c57c6482630e6b2bb299eebf164e187ea7df0a0eb80ecc6)

Going with the same approach as before, I took a look at the report of the different vendors under MalwareBazaar page and found again 3 different families:

![image-6.png](/assets/images/Kraken-Keylogger-pt2/6.png)

I once again checked if our suspicious `Kraken` string can be found either in [JoeSandbox](https://www.joesandbox.com/analysis/864080/0/html) or [UnpackMe](https://www.unpac.me/results/fb8809b4-7327-4621-8b3b-4cdbdfa5b66e/#/) reports and guess what? 

![image-7.png](/assets/images/Kraken-Keylogger-pt2/7.png)

![image-8.png](/assets/images/Kraken-Keylogger-pt2/8.png)

Kraken was found in both of them once again.<br>
At this point I felt comfortable with my findings from the C2 IOC. <br>
Let's move to the second domain we have.

# masherofmasters.cyou Analysis

Typically when I encounter a domain I will investigate it in 3 main sources:
1. VirusTotal
2. URLscan
3. URLhaus

those 3 are my ***go to*** sources for inital domain information gathering.

## VirusTotal

Looking at the domain on VirusTotal can give us a lot of data, such as DNS records, JARM fingerprints, SSL Certs, WhoIS lookup and much more, but the interesting part that I look when doing a proactive hunt is the [Relations tab](https://www.virustotal.com/gui/domain/masherofmasters.cyou/relations) , this tab can tell us which IP's this domain was assigned to, if it has subdomains and which **associated files** this domain had connection with:

![image.png](/assets/images/Kraken-Keylogger-pt2/9.png)

Based on the given list, we can see that 5 files were `.lnk` files, which correlated with our execution flow explained in part 1. (from here you can take the files and see the execution flow when they're detonated and compare to your findings)

## URLscan

Unfortunetlly at the time of investigation the domain was already terminated and no previous scans were made on URLscan so I couldn't find nothing about it here...

## URLhaus

When I searched the [domain in URLhaus](https://urlhaus.abuse.ch/browse.php?search=masherofmasters.cyou) I found about 12 hits:

![image-2.png](/assets/images/Kraken-Keylogger-pt2/10.png)

Some of the files are being flagged as `MassLogger` others were flagged as `SnakeKeylogger` and also `AgentTesla` , I investigated all the files and actually the ones that were marked as `AgentTesla` were indeed that malware but the samples which were flagged as `MassLogger` and `SnakeKeylogger` were actually our beloved `Kraken`...

# UnpackMe Yara Hunt

[UnpackMe](https://www.unpac.me/#/) provides a unique service of proactive lookback on samples analyzed by the platform based on a given [Yara rule](https://github.com/VirusTotal/yara) <br>
The rule I've created was simply based on unique strings that I found in the sample:
```vb
rule Win_KrakenStealer {
    meta:
        description = "Win_KrakenStealer rules"
    strings:
		$s1 = "KrakenStub" ascii wide
		$s2 = "KrakenStub.exe" ascii wide
		$s3 = "Kraken_Keylogs_" ascii wide
		$s4 = "Kraken_Password_" ascii wide
		$s5 = "Kraken_Screenshot_" ascii wide
		$s6 = "Kraken_Clipboard_" ascii wide
		$s7 = "KrakenClipboardLog.txt" ascii wide
		
    condition:
        uint16(0) == 0x5a4d and 5 of ($s*)
}
```

And here is the result of the [hunt](https://www.unpac.me/yara/results/0c947a38-329e-4d2d-8cac-b250ac16c73d):

![image.png](/assets/images/Kraken-Keylogger-pt2/11.png)

In a 12 weeks lookback there were 11 samples that fitted the given Yara Rule, **8** of them were marked as `MassLogger`, so I took a look at [one of them](https://www.unpac.me/results/133f1658-0a19-4355-bfbc-983d8ee80d4e?hash=3d680334931e422f3876eaa6df752da015a902270f73cdfb8f6812910b48c3c2#/)

![image-2.png](/assets/images/Kraken-Keylogger-pt2/12.png)

and by simply looking at the `File Version Information` we can see that it's 99% our `Kraken` , I downloaded the sample and opened it in `DnSpy` and guess what? 

![image-3.png](/assets/images/Kraken-Keylogger-pt2/13.png)

It was our `Kraken`! so we found about 11 samples that are flagged falsely.<br>
And with that our hunt for samples is done, from here you can pretty much correlate some IOC's so see whether or not it's the same threat actor.

# OSINT Research

At this part I wanted to try and find the origin of the malware, so I tried two things:
1. Search engine dorking
2. Underground forums

## Search Engine Dorking

I tried to search the term `"KrakenStub" malware` both in Google and DuckDuckGo, besides giving me 2 analysis one of JoeSandbox and the second one of Vmray I couldn't finding anything useful but it always good to try and search using search engines because you can't really know what you can find...

## Underground Forums

there are several underground/hacking forums that you can find on the clean web without the needs going to TOR and pivoting around the darknet.<br>
One of the most known hacking forums out there is [HackForums](https://hackforums.net/) , so I tried my luck and searched through the marketplace forum for "Kraken" keywords, and after quite some time and found [this thread](https://hackforums.net/showthread.php?tid=6228252) :***#1 KrakenKeylogger | 3 Senders | E-Mail Client & Browser Recovery | Perfect Features*** sold by a user named `Krakenz`:

![image.png](/assets/images/Kraken-Keylogger-pt2/14.png)

What a perfect hit!<br>
that particular finding made my day, I knew that this is it, I've closed the circle and I can close this case and fully resolved.

# Extra Findings

After I've published part 1 of analyzing the Kraken, [@jw4lsec](https://twitter.com/jw4lsec) and me had a small conversation and he shared with me that Windows Defender was flagging the sample I've shared during the investigation as a different malware upon each different execution attempt:

![image.png](/assets/images/Kraken-Keylogger-pt2/15.png)

![image-2.png](/assets/images/Kraken-Keylogger-pt2/16.png)

# Summary

In the 2nd part of analyzing the Kraken I've showed you my way of thinking and approach to the process of threat hunting, especially when your guts tells you that something here is not right. I hope that during those 2 parts of analysis you've learned new things, feel free to PM me via any social media.
