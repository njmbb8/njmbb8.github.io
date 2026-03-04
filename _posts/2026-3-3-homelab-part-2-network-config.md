---
title: "Virtual Active Directory Lab for Pentest Practice Part Two: Network Setup"
author: "Nate McGraw"
---

- [Accessing the OPNSense web inteface](#accessing-the-opnsense-web-inteface)
- [Configuration wizard](#configuration-wizard)
- [Creating the Attacker VLAN](#creating-the-attacker-vlan)
- [Connecting the Firewall to the New Lan](#connecting-the-firewall-to-the-new-lan)
- [Creating a DMZ](#creating-a-dmz)


# Accessing the OPNSense web inteface

In the DC, open your OPNSense's IP address in your browser of choice and login with the root credentials that you created earlier. Once signed in, you should be greeted with a configuration wizard. If you are not, or you clicked away and need to get back to it, there is a wizard option in the sidebar.

![](/assets/img/ad_lab/fw_wizard.png)

# Configuration wizard

The options that you choose here are mostly up to you to decide such as your hostname, what domain you chose, and what dns servers to use. 

The one caveat is that you need to have the DC that we set up as a DNS server as well as your preferred external DNS servers.

For reference, these are the settings that I used. All other settings were left default.

![](/assets/img/ad_lab/wizard_settings.png)

On the next screen, uncheck "Block RFC1918 Private Networks" and "Block bogon networks" then click "Next". 

On the next page, uncheck "Configure DHCP server" and click "Next". 

On the next page, "Cofiguration Wizard", uncheck all of the boxes and click next.

Set your root password (keep it the same or change it if you'd like). and click finish.

# Creating the Attacker VLAN

Go to virt-manager andcreate another network as we did previously, this will be the lan that the attacker machine will be on. Having them on different vlans will allow the firewall to restrict what ports are restricted on what hosts in the network. This time, DHCP can be left enabled unless you would like to manually assign IP addresses on the "WAN". The IP range should be different from the one that was assigned to the ad_internal network.

![](/assets/img/ad_lab/wan_settings.png)

# Connecting the Firewall to the New Lan

Go back to the firewall in virt-manager and create another interface on the host and set the network source to the network that you just created.

![](/assets/img/ad_lab/wan_inteface.png)

Access the firewall's web interface from the DC and click add on the new interface. you should now see it in the list of interfaces as OPT1.

Select OPT1 in the interfaces list in the sidebar and enable the interface, change the IPv4 Configuration Type to "Static IPv4" and set the IPv4 Address to 10.200.1.1/24(adjust depending on the ip range of the network you just created). When you are satisfied with your configuration, click save and then "Apply Changes".

# Creating a DMZ

As I am trying to simulate an enterprise network, the DC should not be directly exposed to the WAN and the machines that are on the WAN should be on a separate subnet from the machines that are exposed to the WAN to limit an attacker's access in the event of a breach. Go ahead and repeat the steps obove to create another network and interface which will be labeled OPT2 in OPNSense.

The network now has the basic set up needed to practice most attacks for now. eventually, a subdomain and other domains will be added on different subnets to practise abusing domain trusts but what we have now is fine. In the next module, we'll add our Kali Linux attacker machine and configure it to be able to reach the lab as well as the WAN so that it can be used for hack the box and other similar platforms as well as the lab.