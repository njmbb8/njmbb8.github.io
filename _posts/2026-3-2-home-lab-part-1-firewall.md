---
title: "Virtual Active Directory Lab for Pentest Practice Part Zero: Setting up a Firewall"
author: "Nate McGraw" 
---

- [Creating a virtual network for the AD environment:](#creating-a-virtual-network-for-the-ad-environment)
- [Creating the Firewall VM:](#creating-the-firewall-vm)
- [Configure the firewall](#configure-the-firewall)


I finished the course material for Zero Point Security's CRTO and wanted an opportunity to practice the techniques outside of the timed labs provided through the course. As a penetration tester, I also want to fully understand how these vulnerabilties are introduced and what can be done to solve them. To accomplish these tasks, I'm going to be creating a virtual AD lab to practice and understand the vulnerabilties on a deeper level than the already deep coverage provieded in the course.

I'm going to be using KVM and virt-manager on Linux Mint to handle virtualization. The network AD environment will expand as I go but the current plan uses Windows Server 2025 and Windows 11 machines to mimick an enterprise AD environment. I'll introduce vulnerabiltiies covered in the course such as Kerberoasting and Delegation Abuse. I'm also going to be adding vulnerabilities to practice ESC stle ADCS abuses.

Having a vulnerable environment in my network could be a scary concept so I'll be using OPNSense as a firewall to cordon off the test AD and tightly control what comes into and out of the environemnt over the network. I'm going to skip setting up the virtualization management(KVM and virt-manager) as it is not that hard and, in my opinion, out of scope for this blog.

# Creating a virtual network for the AD environment:

The first thing that needs to be done is to create a virtual and isolated network for our AD. The firewall will be able to connect to the internet and determine what traffic is allowed through. In order to do that, it needs two interfaces(more on that in the next step) connected to both the WAN(internet) and the active directory LAN(if this were a company, it would be their internal network or intranet). In virt-manager, make sure that QEMU/KVM is selected and then click Edit-> "Connection Details". Click the plus button in the corner(it has an arow pointing to it in the screenshot) and then name your network, set it to an isolated type, give it an IP range and disable DHCP(the Domain controller will handle DHCP). The name and the IP range do not have to be the same as mine but the following screenshot s the settings that I am using.

![](/assets/img/ad_lab/network_config.png)

# Creating the Firewall VM:

Starting out, your virt-manager window should look something like mine. To start a new VM, click the "Create a new virtual machine" button that has an arrow pointing to it.

![](/assets/img/ad_lab/kvm_init.png)

Choose the option to install from a .iso image, download the most recent OPNSense .iso from the [OPNSense download page](https://opnsense.org/download/). Uncheck OS selection and select "generic linux 2024". OPNSense is based on FreeBSD so if you have a corresponding option, you can select that but I didn't so I didn't. 

![](/assets/img/ad_lab/install_media.png)

For the rest of the settings, I gave it 2 CPU cores, 4096 MB of memory, and 20 GB of storage. Also be sure to check "Customize configuration before installing" so that you can give it another network interface so that it can connect to the WAN and the AD LAN.

![](/assets/img/ad_lab/fw_settings.png)

You should now be presented with a configuration screen for the VM. Click "Add Hardware", then select "Network" on the sidebar, change the network to the one you just created, and the nclick "Begin Installation". At this point, you can just let the installer run. There is an opportunity to halt set up and configure it manually but for the sake of making the guide easy to follow, we'll do all of that once the machine is up and running.

# Configure the firewall

Once you are presented with a logon, use the default credentials of `installer:opnsense`, select the correct keyboard for your setup, install ZFS, change the root password, and reboot the machine. Once the machine comes back up, login as root with the password you just set up, select option 1 to assign interfaces because the automatic setup almost certainly got it wrong. Set the WAN interface to the one that was automatically configured when the machine was set up and set the LAN to the one you created. If you are unsure about which is which, you can go back to the configurations that were set by clicking the information button and the interface can be identified through its MAC address.

![](/assets/img/ad_lab/network_interfaces.png)

The next step is to make sure that IP addresses have been assigned correctly. If you have DHCP enabled on your network, the WAN interface is likely to not need manual assignment but the LAN interface will need to be configured. Select option 2 at the OPNSense main menu and then select the LAN interface. Since this is a gateway, it needs to be the first IP address in the range so I'm giving mine an IP of 10.200.0.1 and a CIDR range of 24 which corresponds to a subnet mask of 255.255.255.0. Say no to all of the IPV6 stuff and decide whether or not HTTPS makes sense for the web interface in your case. I'm not using HTTPS as the interface will not be externally exposed, I do not have to worry about my traffic being sniffed. When the configuration is done, you will be presented with an IP address from which to access the web interface. The web interface is, by design, only accessible from the LAN so it will not be available until we add the DC to the LAN in the next step. 