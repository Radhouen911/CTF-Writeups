# The Hill Surveillance - Writeup

## Challenge Overview

**Name:** The Hill Surveillance  
**Category:** 8-BIT PIXEL PALACE  
**Difficulty:** Easy  
**Points:** 500  
**Flag:** `CM{surveillance_through_the_webcam_feed_8bit}`

### Description

📡 **THE HILL SURVEILLANCE**

Deep in the pixelated mountains, an access point called "The Hill" broadcasts from an abandoned surveillance station. They say someone up there is always watching the valley below.

You've intercepted a password: "buttercupde". The signal is strong. The network is active. Something is recording.

The Hill sees all. What does The Hill see?

---

## Challenge Scenario

## This challenge was a physical/on-site network reconnaissance task that took place at the Engineers Spark Lab during the CTF event. Participants needed to perform network enumeration on a local wireless network to discover surveillance equipment and capture the flag.

## Solution (Theoretical Walkthrough)

**Note:** Unfortunately, I couldn't capture screenshots during the event, so this writeup covers the theoretical approach and methodology used to solve the challenge.

### Stage 1: Connect to the Network

**Objective:** Connect to "THE HILL" wireless access point

**Steps:**

1. Navigate to the Engineers Spark Lab (physical location)
2. Scan for available WiFi networks
3. Connect to the access point named **"THE HILL"**
4. Use the provided password: **`buttercupde`**

Once connected, you should receive an IP address in the `192.168.1.x` range.

---

### Stage 2: Network Reconnaissance

**Objective:** Discover active hosts and services on the network

After connecting to the network, perform network enumeration to discover what devices and services are available.

#### Method 1: Using Nmap

```bash
# Discover your IP address
ip addr show
# or
ifconfig

# Scan the entire subnet for active hosts
nmap -sn 192.168.1.0/24

# Example output:
# Nmap scan report for 192.168.1.1
# Host is up (0.001s latency).
#
# Nmap scan report for 192.168.1.2
# Host is up (0.002s latency).
```

#### Method 2: Using arp-scan

```bash
# Scan the local network
sudo arp-scan --localnet

# or specify the subnet
sudo arp-scan 192.168.1.0/24
```

#### Method 3: Using netdiscover

```bash
# Passive network discovery
sudo netdiscover -r 192.168.1.0/24
```

**Key Finding:** You should discover an active host at **`192.168.1.2`**

---

### Stage 3: Service Enumeration

**Objective:** Identify open ports and services on the discovered host

Perform a port scan on the discovered host to find running services:

```bash
# Quick scan of common ports
nmap 192.168.1.2

# Full port scan
nmap -p- 192.168.1.2

# Service version detection
nmap -sV -p- 192.168.1.2
```

**Expected Results:**

The scan should reveal multiple open ports, including:

- **Port 21** - FTP (File Transfer Protocol)
- **Port 8888** - HTTP (Web service / Webcam feed)
- Other common services (intentionally enabled for easier discovery)

**Key Finding:** Port **8888** is hosting a web service

---

### Stage 4: Access the Webcam Feed

**Objective:** Access the surveillance webcam and retrieve the flag

Once you've identified port 8888, access it through a web browser:

```bash
# Open in browser
http://192.168.1.2:8888


**What you'll find:**

The web service on port 8888 hosts a **webcam surveillance feed**. The webcam is pointed at a physical location where the flag is written on a piece of paper.

**Flag Location:** The flag `CM{surveillance_through_the_webcam_feed_8bit}` is visible on the paper in the webcam preview.

```

## Step-by-Step Summary

1. **Connect** to "THE HILL" WiFi access point using password `buttercupde`
2. **Discover** active hosts on the `192.168.1.0/24` network
3. **Identify** host `192.168.1.2` with open services
4. **Scan** ports on `192.168.1.2` to find port 8888
5. **Access** `http://192.168.1.2:8888` in a web browser
6. **View** the webcam feed showing the flag on paper
7. **Submit** the flag: `CM{surveillance_through_the_webcam_feed_8bit}`

---

📡 **The Hill sees all. Now you see what The Hill sees.** 📡

```

```
