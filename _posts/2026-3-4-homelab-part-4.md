---
title: "Virtual Active Directory Lab for Pentest Practice Part four: Creating a Mangement VPN"
author: "Nate McGraw"
---

- [Creating a VPN to access the management](#creating-a-vpn-to-access-the-management)
- [Creating a Peer in OPNSense Wireguard](#creating-a-peer-in-opnsense-wireguard)
- [Installing WireGuard and creating a configuration file](#installing-wireguard-and-creating-a-configuration-file)
- [Creating a Firewall Rule to Allow VPN Handshakes](#creating-a-firewall-rule-to-allow-vpn-handshakes)
- [Creating a Firewall Rules to Allow connections from the VPN to other device](#creating-a-firewall-rules-to-allow-connections-from-the-vpn-to-other-device)
- [Test out the connection](#test-out-the-connection)
- [Changing the firewall's lan to the VPN network](#changing-the-firewalls-lan-to-the-vpn-network)
- [Creating Firewall Rules for the DC's connectivity](#creating-firewall-rules-for-the-dcs-connectivity)


After considering how to address this, I've decided that it would be best to make this its own post because anyone following along would still have a functional set up until this point. I was preparing to set up the networking on the Kali machine and realized that I had made an error: the gateway should be in its own VLAN because traffic to and from the gateway is unique, and it does not belong to the hackable.lan domain. 

In this guide, we'll be creating a "management network" and put the firewall in it. Then we'll create firewall rules to restrict access to the web interface so that it can only be accessed from a VPN connection. The idea here is to have the host machine be able to access the web interface directly without needing to spin up another VM which is the current setup.

# Creating a VPN to access the management 

Open the OPNSense web interface in your DC and click VPN ⇾ WireGuard ⇾ Instances and click the plus button to add a new instance.

![](/assets/img/ad_lab/wireguard.png)

Fill the settings as I have above or tweak them to your needs. Make sure to copy the public key as you'll need that for the configuration file being built in the next step.

Got to Interfaces ⇾ Assignments and there should be a new and unassigned interface. Give it a description such as mgmt_vpn and click Add. Then go to the interface and enable it.

Open Interfaces ⇾ \[WAN\] and uncheck "Block private networks" and "Block bogon networks", then click save.

Reboot the OPNSense VM and then go to Interfaces ⇾ Assignments, Give the wg0 interface a name and click Add.

# Creating a Peer in OPNSense Wireguard

Go back to the OPNSense web interface and click VPN ⇾ WireGuard ⇾ Peer generator in the sidebar.

Set the endpoint to the firewall's IP address on the WAN interface. This can be found in virt-manager by clicking on the info button(the blue circle with the i on it) on the firewall VM and opening the network interface connected to the default network. This should include the VPN listening port in the format IP:Port.

![](/assets/img/ad_lab/firewall_ip.png)

Enter the address that you'd like to provide to the host in the Address field and copy that value to the Allowed IPs field. This way, the host is the only machine allowed to connect to the management interface, but this can be expanded later.

Set the keep alive timeout to 25 or else the connection will not work.

Copy the text in the config section and click the checkbox next to "Store and generate next". Make sure to check the box for "Enable WireGuard" and then click Apply.

![](/assets/img/ad_lab/wg_peers.png)

# Installing WireGuard and creating a configuration file

On your host, run the following to install wireguard:

`sudo apt update && sudo apt install wireguard -y`

Create config file and open it in nano by running: `sudo nano /etc/wg0.conf` and pasting the contents of the Config section of the peer generator. 

# Creating a Firewall Rule to Allow VPN Handshakes

In the sidebar, click Firewall ⇾ Rules \[new\]. Click the + icon in the bottom right to create a new rule.

Change the protocol to UDP.

Set the Source to Single Host or Network with a value of 192.168.122.1. This effectively ensures that only local connections will be allowed as that is the IP address of the WAN bridge interface.

Set the destination as "WAN address" and the destination port to "Single port or range" with a value of 51820.

All other settings should be left as default and the settings should match the screenshot below. Then click Save and then Apply.

![](/assets/img/ad_lab/vpn_handshake_rule.png)

# Creating a Firewall Rules to Allow connections from the VPN to other device

The only real connection being made thus far is the web interface which may change in the future and more rules can be created. First create a rule with the interface being the management VPN interface set the source as your host machine. Set the destination as the IP of the web interface, the protocol to TCP and the destination port to 443. Create another identical one for port 80 to handle the redirect and make things run smoothly.

![](/assets/img/ad_lab/web_ui_vpn_rule.png)

# Test out the connection

With the config file generated from the peer generator and the firewall rules in place, we should be able to access the web ui from the host machine!

On the host run `sudo wg-quick up wg0` and open a browser to http://10.200.254.1/, and you should be redirected to a login page at https://10.200.254.1/. If not, run back through the steps and see if you missed something. If everything looks good, go ahead and move on to the next step!

# Changing the firewall's lan to the VPN network

Now that access is set up, The Active Directory LAN and the WireGuard interface need to be switched. Go to Interfaces ⇾ Assignments and use the dropdown to change the device for the interface with the identifier of "LAN" to wg0 and then change the device for the interface that that was formerly for the management VPN to vtnet1(or whatever the device that was on the LAN interface was) and then click save.

![](/assets/img/ad_lab/upodated_interfaces.png)

Now update their names and the IP address range for the AD_LAN(you can't set IP addresses on a tunnel interface). 

# Creating Firewall Rules for the DC's connectivity

Now that the wg0 interface is the LAN, an automatically generated anti-lockout rule applies that allows any connection from the interface will be allowed so the rules regarding web UI access can be deleted.

A rule now needs to be created to allow DNS, NTP, and HTTP/S to support necessary windows functions such as clock synching and updates.

The first rule that will be created is to support DNS. Create a rule with the ad_lan as the interface, change the source to "ad_lan net" so that all the machines on the internal AD domain will have DNS support. Set the protocol to UDP and the destination port to "Single port or range" with a value of 53.

The next rule will support Network Time Protocol(NTP) for the DC. All the machines in the domain will use the DC as an NTP server, so only the DC needs NTP traffic. The rule will be similar to the previous one, but the source will be the DC IP and the destination port will be 123.

Next, two ad_lan-wide rules will be created. One for port 80 and one for port 443. This way, all the AD joined machines will be able to reach out to the internet which is realistic for an enterprise environment. You should now be able to run updates on your AD's DC.