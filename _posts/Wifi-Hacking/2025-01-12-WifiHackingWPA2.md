---
title: "How to Crack WPA2 Wi-Fi Passwords"
classes: wide
header:
  teaser: /assets/images/Wifi-Hacking/logo.png
  overlay_image: /assets/images/Wifi-Hacking/logo.png
  overlay_filter: 0.5
ribbon: OliveDrab
excerpt: "Discovering WPA2 Wi-Fi passwords on Linux using airodump-ng, airmon-ng, and aircrack-ng."
description: "Discovering WPA2 Wi-Fi passwords on Linux using airodump-ng, airmon-ng, and aircrack-ng"
categories:
  - Wi-fi Hacking
tags:
  - Wi-fi
  - WPA2
  - Linux
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
---

# Intro
In this post, I will demonstrate, for educational purposes only, how to uncover the password of a WPA2-PSK Wi-Fi network. Please note that performing such actions without explicit authorization from the network owner is illegal and may result in serious consequences. This content is intended solely for ethical hacking and security research.

# Requirements
To get started, you’ll need a USB Wi-Fi adapter that supports monitor mode. This is necessary if your built-in network card does not support monitor mode or if you are using a virtual machine, as most virtual machines cannot access built-in Wi-Fi cards directly. Additionally, you’ll need an environment running a Linux-based operating system; in this case, we’ll be using Kali Linux.

For this tutorial, I’m using the TP-Link USB 150Mbps TL-WN722N Wireless Adapter, which supports monitor mode. However, keep in mind that this adapter only works on 2.4GHz networks, so it won’t be able to capture traffic or perform operations on 5GHz networks.

# Understanding Wi-Fi and WPA2
Before we begin, it’s important to clarify some key concepts:

Wi-Fi, the technology that enables wireless connections between devices, relies on encryption protocols to secure the communication. These protocols have evolved over time, starting with WEP (Wired Equivalent Privacy), followed by WPA (Wi-Fi Protected Access), WPA2, and the latest, WPA3.

Currently, the most widely used standard is WPA2, an updated version of WPA. WPA2 is based on the Robust Security Network (RSN) mechanism and operates in two modes:

 - WPA2-PSK (Pre-Shared Key): Commonly used in home environments.
 - WPA2-EAP (Extensible Authentication Protocol): Designed for organizational or enterprise use.  

In this post, we will focus specifically on WPA2-PSK, the mode typically used in residential settings.

# How the Attack Works

For better understanding, here’s a brief theoretical explanation:

- [**Set up the environment**](#set-up-the-environment): We will configure the virtual machine to recognize the Wi-Fi adapter and enable monitor mode, allowing us to capture wireless traffic.
- [**Listen to nearby networks**](#listen-to-nearby-networks): We will use tools to "listen" to nearby networks and identify our target.
- [**Disconnect a device from the network**](#disconnect-a-device-from-the-network): We will send deauthentication packets to force a connected device to disconnect from the network.
- [**Capture the handshake**](#capture-the-handshake): When the device reconnects, we will intercept the WPA2 handshake, which contains the hash of the password.
- [**Perform brute force on the hash**](#perform-brute-force-on-the-hash): With the handshake captured, we will perform a brute force attack on the hash to try to discover the password.

You can find more details about the **4-Way Handshake** in WPA2 [here](https://networklessons.com/wireless/wpa-and-wpa2-4-way-handshake).

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/wpa-4-way-handshake-workflow.png" alt="4-Way Handshake Diagram">
</div>


## Set up the environment
Primeiramente, conectamos o adapatador USB no computador ou notebook.
Adicionamos o adaptador nos dispositivos de entrada da máquina virtual
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/opcoes_vb.png" alt="4-Way Handshake Diagram">
</div>
![alt text](image.png)

## Listen to nearby networks
We will use tools to "listen" to nearby networks and identify our target.

## Disconnect a device from the network
We will send deauthentication packets to force a connected device to disconnect from the network.

## Capture the handshake
When the device reconnects, we will intercept the WPA2 handshake, which contains the hash of the password.

## Perform brute force on the hash
With the handshake captured, we will perform a brute force attack on the hash to try to discover the password.
