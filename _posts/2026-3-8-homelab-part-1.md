---
title: "Virtual Active Directory Lab for Pentest Practice Part One: Designing and creating the network"
author: "Nate McGraw"
---

While practicing for Zero Point Security's CRTO course, I felt a need to create an environment where I could practice the TTP's that I learned in the course without a timer. I also wanted to practice attacks not covered in the course such as ADCS abuse.

I have a beefy enough computer, so I decided to try to create an offensive security testing lab using VMs. To accomplish this, I'll be using virt-manager to manage the VMs and KVM as a hypervisor.


- [Network Requirements](#network-requirements)
- [Creating Virtual Networks](#creating-virtual-networks)


# Network Requirements

Before I start building anything, I want to lay out what my networking needs are as the networks have to be created prior to an interface being added.

The first requirement is a firewall to act as a gateway for all the subnets and to regulate what can and can not be accessed between them. I'm going to use OPNSense for this which is managed by a web based UI. I want to limit access to the web UI to machines joined to a VPN which will require another subnet.

As far as the actual lab section of the infrastructure, I'm going to have a subnet to simulate the WAN which will have two interfaces on it. One interface on the Kali machine and one on a Linux web server which has another interface in a DMZ.

The web server in the DMZ will be connected to an MSSQL server on another subnet which will act as an internal network with an active directory domain and DC.

I'm planning on performing web attacks as well as active directory attacks. I want to create a way to do AD attacks without having to re-exploit a web attack, so I'm going to create another VPN to give the Kali a machine direct access to the internal AD environment.

![](/assets/img/ad_lab/part_one/network_diagram.png)

# Creating Virtual Networks

By my count, I need to create 4 virtual networks in Virt Manager and 2 VPNs in OPNSense which will come later. I disabled DHCP on all of them because OPNSense or the DC in the case of the internal subnet. DHCP is disabled in the management network because everything will be statically assigned. I'm using /24 IP ranges which may be a bit overkill for the few devices that I'm using, but I'm not hurting for free IP space and using the third octet as an identifier for which subnet is which is convenient for me.

| Interface |     Name    |      subnet      |
|-----------|:-----------:|:----------------:|
| vtnet1    |     mgmt    | 192.168.100.0/24 |
| vtnet2    |   attacker  |    10.0.1.0/24   |
| vtnet3    |     dmz     |    10.0.2.0/24   |
| vtnet4    | ad_internal |    10.0.3.0/24   |
