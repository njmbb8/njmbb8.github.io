---
title: "Virtual Active Directory Lab for Pentest Practice Part Three: Adding the Attacker Machine"
author: "Nate McGraw"
---

- [Creating the Virtual Machine](#creating-the-virtual-machine)
- [Quality of Life Upgrades](#quality-of-life-upgrades)
- [Installing Sliver C2](#installing-sliver-c2)
- [I made a mistake!](#i-made-a-mistake)


In this step, we'll be adding a creating a Kali Linux VM to attack our AD network. The idea is to simulate an attacker from an untrusted external network. A VPN can be added later so that an attack can be launched from the perspective of an assumed breach or just so that the DMZ would not need to be re-exploited every time I want to test something in the internal network.

# Creating the Virtual Machine

This process is going to be very familiar from the machines that we've created before. Download a Kali Linux .iso from [the official source](https://www.kali.org/get-kali/#kali-installer-images). Create a new VM in virt-manager with that .iso as the source and select Debian 13 as the operating system. 

As I'm planning on using this for other challenges, I gave my system significantly more than the recommended minimum requirements: 4 CPUs, 8 GB of memory, and 120 GB of storage.

Make sure to check the "Customize configuration before install" option to add another network interface for the simulated WAN. When installing Kali, make sure that you set the primary interface as the one with internet access.

The domain is not necessary here but if you do set one, be sure not to set it as the same domain as the Active Directory one.

# Quality of Life Upgrades

Once your Kali machine boots up, log in with whatever credentials you created. If your screen is the wrong size for the window, or you can not paste into your machine, run:

```
sudo apt update && sudo apt upgrade -y && sudo apt install qemu-guest-agent spice-vdagent
sudo systemctl enable qemu-guest-agent spice-vdagent
sudo systemctl start qemu-guest-agent spice-vdagent   
```

Once you reboot the computer, go to View ⇾ Scale Display ⇾ Always and check the box for "Auto Resize VM with Window". You should now be able to share your clipboard with the VM and the screen should adjust to the window resizing.

# Installing Sliver C2

In order to keep up to date with modern TTP's, I'm going to be using Sliver C2 in this lab. I would love to use Cobalt Strike but it's a little cost prohibitive.

Sliver C2 is a popular and modern FOSS C2 that can handle BoFs like Cobal Strike can and has the same level of customization allowing you to create stealthy beacons.

To install sliver, you can do so by running `curl https://sliver.sh/install|sudo bash`. If piping a random script from the internet into an privileged shell skeeves you out, good! feel free to check the script first or build from ource according to the directions provided by Bishop Fox.

# I made a mistake!

It happens to the best of us sometimes. I was going to configure networking in Kali when I realized that the gateway needs to be in its own subdomain. I'll fix that in the next post. That will make configuring the network much simpler.