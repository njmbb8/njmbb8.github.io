---
title: "Virtual Active Directory Lab for Pentest Practice Part Three: Creating the Domain"
author: "Nate McGraw"
---

The Active directory network will follow a pretty typical lab setup with a vulnerable machine on the DMZ which is used to pivot to a domain controlled machine which is used to escalate privileges in the domain against the DC.

Before I create a vulnerable domain, I must make the domain controller and all the changes needed to do so(firewall rules, VM creation, etc.)

# Firewall Rules to Support the AD

While I want the internal network to be isolated, I still want it to be able to access the internet for the purposes of updates or downloading scripts. The DC will also need access to NTP services and DNS services so that it can then provide those services to the rest of the domain.

# Creating the DC

Windows provides evaluation editions of the various windows versions that are valid for 180 days. I'm using the Windows Server 2025 evaluation edition for the servers in the domain, using the ISO to create a new VM with the network attached to the interface being the internal AD network.

I gave the VM 2 CPU cores, 8 GB of memory and 60 GB of storage. When presented with the opportunity for which version of Windows to install, I went with the desktop experience version because the GUI makes things so much easier. If I'm having resource issues down the road, I'll redo the DC without the DE.

![](/assets/img/ad_lab/part_three/DC_FW_rules.png)

# Promoting the Server to DC

![](/assets/img/ad_lab/part_three/DC_IP_settings.png)

Once I was signed into the DC, the first task was to assign it a static IP address so that it can have network connectivity because it currently has an APIPA. No rule was created to allow ICMP traffic so ping can not be used to verify network connectivity but nslookup works and I am able to load external web resources.

![](/assets/img/ad_lab/part_three/DC_connection.png)

With a static IP address assigned to the DC, I went to the Server Manager and installed the Active Directory Domain Services. 

Once the ADDS was installed, I promoted the machine to a domain controller and added a new forest with a root domain name of `hackable.lan`. All other options were left as default and I passed the prerequisite check so I clicked Install.

![](/assets/img/ad_lab/part_three/DC_prereq_check.png)

# DHCP Configuration

I installed the DHCP server feature on the DC and then clicked "Complete DHCP configuration". The defaults were fine so I clicked through it. I then went to DHCP under Tools in the top right and configured a new scope using the OPNSense gateway as the gateway and the DC for the other servers.

# Quality of Life Improvements

I added the [virtio-win](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso) image from Fedora to the disc drive of the DC. and ran the `virtio-win-guest-tools.exe tool on it. After it installed, I was able to enable automatic screen resizing and clipboard sharing.