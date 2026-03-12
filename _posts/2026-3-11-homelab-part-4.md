---
title: "Virtual Active Directory Lab for Pentest Practice Part Four: Creating the Kali Attack Machine"
author: "Nate McGraw"
---

Now that the DC and domain are up, we can create the Kali machine and a VPN to connect to so that attacks against the DC could be performed, and I can get a bit of a reward by having some fun.

- [Creating the VM](#creating-the-vm)
- [Enabling DHCP in OPNSense](#enabling-dhcp-in-opnsense)
- [Creating an "Allow All" Firewall Rule for the Attacker Subnet](#creating-an-allow-all-firewall-rule-for-the-attacker-subnet)
- [Building the Environment](#building-the-environment)
  - [Update and Upgrade](#update-and-upgrade)
  - [Guest Agent](#guest-agent)
  - [Sliver C2](#sliver-c2)
  - [Wireguard](#wireguard)
- [Creating the VPN to Grant Access to the Internal Network](#creating-the-vpn-to-grant-access-to-the-internal-network)
  - [Creating the New Instance](#creating-the-new-instance)
  - [Creating the Firewall Rules](#creating-the-firewall-rules)
  - [Adding a Peer for the Kali Machine](#adding-a-peer-for-the-kali-machine)


# Creating the VM

I added the latest Kali image to a new VM and gave the VM two interfaces. One for the default WAN network to reach the internet without going through OPNSense if I'm doing bug bounty of CTF. The second interface is for the attacker network, the simulated WAN that the Kali machine will access the DMZ from.

I was having issues with the Kali interfaces keeping their DHCP assignments, so I set each interface to be of model e1000e which solved the issue for me. Apparently the driver is more reliable.

# Enabling DHCP in OPNSense

I spent a lot of time troubleshooting why DHCP requests were working for the WAN interface but not for the attacker_net interface. I eventually found that in OPNSense, the DHCP service needs to be told what interfaces to listen on, so I configured it to listen on all interfaces that are using OPNSense for a DHCP server. I also added a DHCP option to create a classless static route for any machine on the subnet.

![](/assets/img/ad_lab/part_three/DHCP_Options.png)

# Creating an "Allow All" Firewall Rule for the Attacker Subnet

The network that Kali is on should mimic a WAN, so I'm creating an allow all rule on the attacker_net subnet so that there are no restrictions on what the attacker can send or receive, as in a real world scenario.

# Building the Environment

Kali comes with a great deal of pentesting tools already, but there are two additions that I already know that I am going to need to make:

## Update and Upgrade

The first thing is to make sure that I'm running with the latest and greatest tools. so I'm going to run `sudo apt update && sudo apt upgrade -y`. This predictably took quite a while, so I went to grab a Red Bull and let the puppy out.

## Guest Agent

Just like I did with the DC, I am going to install tools to allow clipboard sharing and dynamic screen sizing. I ran `sudo apt install -y qemu-guest-agent spice-vdagent xserver-xorg-video-qxl` and then rebooted which gave me the abiltiy to enable the "Auto resize VM with window" and enabled the shared clipboard.

## Sliver C2

I recently finished up with Zero Point Security's CRTO course which made heavy use of the Cobalt Strike C2 framework. While working in this lab, I would like to keep my attacks as modern as possible, but I do not have Cobalt Strike money. From my research, Sliver is going to be the best alternative. 

In Kali, installing Sliver is really easy: `sudo apt install -y sliver`. I will go into depth on how to use Sliver in a future blog post but for now, as long as it's installed I can move on.

## Wireguard

I want to have a VPN connection that optionally gives the Kali machine direct access to the internal network with the AD on it. I'm using WireGuard to handle my VPN needs for this lab, so it will be installed on this machine.

# Creating the VPN to Grant Access to the Internal Network

I have to go through creating another VPN. It should be a little easier the second time. Create a VPN instance, assign and enable the interface, create some allow rules in the firewall and generate a peer. EZPZ right?

## Creating the New Instance

Pretty standard process here, I gave it a Tunnel Address of 10.0.100.1/24 and a listening port of 51821

## Creating the Firewall Rules 

I started by cloning the existing handshake rule and changing the port to fit my new instance's listening port which was 51821. i also hanged the source IP address to be the Kali machine's IP address.

I cloned the other VPN rule as well allowing traffic between the two subnets and modified it to work with different subnets.

![](/assets/img/ad_lab/part_three/FW_RULES.png)

## Adding a Peer for the Kali Machine

I used the peer generator as I had before and gave it access to 10.0.100.2/32(the Kali machine IP), and 10.0.3.0/24. After connecting and verifying that `sudo wg show` listed a handshake, I tried to ping the DC at 10.0.3.2 which was a success! I also ran enum4linux, an AD enumeration tool, against the domain IP with the DA credentials and was able to get accurate information. 

![](/assets/img/ad_lab/part_three/domain_info.png)

Technically, I have enough to start on the first AD attack that I want to document: AS-REP roasting. I do want to observe the attack from the blue team side though so the next thing that I'll be doing is creating a SIEM and then I can get to AS-REP roasting.