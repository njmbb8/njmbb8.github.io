---
title: "Virtual Active Directory Lab for Pentest Practice Part Five: Creating an Assumed Breach VPN"
author: "Nate McGraw"
---

- [Creating a New Interface](#creating-a-new-interface)
- [Creating Firewall Rules for the VPN handshake](#creating-firewall-rules-for-the-vpn-handshake)
- [Creating a Firewall Rule Allowing traffic between Kali and the AD Network](#creating-a-firewall-rule-allowing-traffic-between-kali-and-the-ad-network)
- [Creating a Peer for Kali](#creating-a-peer-for-kali)
- [Connecting to the VPN in Kali](#connecting-to-the-vpn-in-kali)


The final version of this lab will have machines with services such as web servers that the Kali machine will be able to access and used to cross the DMZ. This is going to be essentially the same process as the VPN in the last step except the connection will come from the Kali machine, so we'll need to account for it being in a different subnet.

# Creating a New Interface

In the sidebar, click VPN ⇾ WireGuard ⇾ Instances and click the + sign to add a new VPN instance. Give it a name and click the gear to generate a key pair. Set the port to 51821.

For the tunnel address field, the tunnel should have its own IP range. I gave mine 192.200.250.1/24.

Leave the "Peers" section empty and everything else default and then click Save and then Apply.

![](/assets/img/ad_lab/breach_vpn_instance.png)

Click Interfaces ⇾ Assignments, give the new WireGuard interface (wg1) a name and click add. Go to the new interface and enable it.

# Creating Firewall Rules for the VPN handshake

As we've already created a VPN handshake before, it can be cloned and modified. Click the clone button on the existing handshake rule and change the port from 51820 to 51821. 

In Kali run `ip a | grep 192.168.122` and take note of the IP address that you get back. Make that IP address the source.

Update the description and click Save.

# Creating a Firewall Rule Allowing traffic between Kali and the AD Network

I don't want any port restrictions here, if the Kali machine is in a trusted network then it should not be restricted by the firewall, so we'll create a rule to pass any traffic between the Kali machine and the AD Network.

![](/assets/img/ad_lab/breach_fw_rule.png)

# Creating a Peer for Kali

Go back to the Peer generator under VPN ⇾ WireGuard and fill in the form like we did previously but updated for the new instance. 

Give it an appropriate name. Change the listening port on the endpoint. Give yourself an IP in the Address field and then put the IP range of the ad internal network in the Allowed IPs range. Give the Keepalive Interval a value of 25.

Once all the fields are correctly filled, copy the config text and click the checkbox next to "Store and generate text".

![](/assets/img/ad_lab/kali_peer.png)

# Connecting to the VPN in Kali

Sign in to the Kali VM and run `sudo apt update && sudo apt upgrade -y && sudo apt install wireguard -y` to install WireGuard.

Enter a privileged shell by running `sudo -i` and changing directories to `/etc/wireguard` and running `umask 077` and then `nano wg0.conf`. Paste in the config information from the peer generator and save the file.

Exit the root shell by running `exit` and connect to the VPN by running `sudo wg-quick up wg0`.

Verify connectivity by running `sudo wg show` and verifying that there is a "latest handshake" field. You should also now be able to ping, nmap, etc. the DC now.

![](/assets/img/ad_lab/kali_conn.png)