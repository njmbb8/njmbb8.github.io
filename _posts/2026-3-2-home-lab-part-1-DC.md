---
title: "Virtual Active Directory Lab for Pentest Practice Part One: Setting up a Domain Controller"
author: "Nate McGraw"
---

With the firewall set up, we can start working on building the Active Directory environment. Without a Domain Controller, there is no Active Directory so we'll start with setting up the domain controller and the domain.

# Setting the VM up

We already discussed how to create a new VM in the previous step. In this case, it will be only slightly different and considerably simpler. As this is not an enterprise environment, I'm going to use the evaluation versions of Windows Server that can be obtained [directly from Microslop](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025). These evaluation editions have license keys which are valid for 180 days.

Because WAN traffic from all AD machines is going through the firewall, and because the firewall has a network interface connected to the internal network, the DC only needs one interface connected to the internal network. When I selected the option to automatically detect the OS from the image, Windows Server 2022 was picked which is incorrect and caused the install to fail. Make sure to avoid this by selecting the 2025 version.

![](/assets/img/ad_lab/dc_pre_install.png)

I'm giving the DC 4096 MiB of ram, 2 CPUs, and 65 GB of storage because that's the recommended settings that I found online. Since I'm the only person generating traffic and because I'm intentionally avoiding heavy workloads to practice stealth, there shouldn't be any issues with resource allotment. On the final screen, make sure that the correct network interface is selected and you're good to go.

# Installing Windows Server 2025

Say what you will abut M$, the install process here is fairly strightforward. The only non-default option that I am using is picking the version with the desktop experience which does increase the overhead on the server but makes things much easier, especially when trying to make a guide.

The machine will reboot several times during the installation, eventually bringing you to a screen where you can enter the Administrator password. Once you have entered one, select the amount of data you want to send and keep the option to manage the server through Server Manager.

# Quality of Life Improvements

The biggest concern here is being able to share clipboards between the host and guest images but there is also the issue of dynamically resizing the screen with the window changing. With a type 2 hypervisor like virtualbox, this would be managed by installing the guest additions images. With KVM, we can use the Virtio Win ISO from the [fedora project](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso).

Going back to the information panel where we added a network device previously, click on the disk drive and change the source path to the virtio-win.iso file that you just downloaded and click apply.

![](/assets/img/ad_lab/virtio-win.png)

Going back to the DC's GUI, run the application virtio-win-guest-tools.exe and then select view -> scale display and click 'always' and 'Auto resize VM with window'. Now you can copy and paste into/out of the virtual machine.

# Network settings

Because DHCP was not enabled on the firewall, we need to manually assign an IP address to the DC because it currently has an [APIPA](https://en.wikipedia.org/wiki/Link-local_address) and can not communicate on the network. 

![](/assets/img/ad_lab/manual_ip.png)

Turn on IPv4 and then configure your netowrk. The following is a screenshot of the settings that I'm using, all options not shown were left on default values: 

![](/assets/img/ad_lab/ipv4.png)

You should now have network connectivity and the ability to make DNS requests.

![](/assets/img/ad_lab/outbound_traffic.png)

# Creating the domain

Open Server manager in the DC(it should have opened automatically when the DC boots but you can find it in the start menu) and click manage(in the top right) and select "Add Roles and Features" and click next on the popups until you get to the Server Roles page. We will add other roles and features in the future but for right now, select Active Directory Domain Services.

![](/assets/img/ad_lab/dc_adds.png)

Click "add features" and keep clicking next and then install when you get the chance. After installation is complete, the flag in the top right corner of Server Manager will have a caution sign on it. Click that sign and then click "Promote the server to a domain controller" and choose "Add a forest". The root domain is up to you. I recommend using a [reserved TLD](https://en.wikipedia.org/wiki/Top-level_domain#Reserved_domains); I'm using "hackable.lan". 

Set the DSRM password to something you can remmeber. If you manage to lock yourself completely out of your domain and don't want to start fresh, you'll need that password.

Keep Clicking next through the Prerequisites Check. If you have any errors or warnings other than the one in the following screenshot, address them. Once they are resolved or if your prerequisites check results look like mine, click install.

![](/assets/img/ad_lab/pre_req.png)

Once your computer has rebooted, sign back in as Administrator and open Server Manager if it doesn't open on its own for some reason. Click on "Local Server" on the sidebar and verify that the "Domain" field is populated.

![](/assets/img/ad_lab/domain_joined_dc.png)

Congratulations, you've just set up a domain controller! Now that we have created a domain and verified that the virtual network is configured correctly, it's time to configure the firewall to simulate our trafic going over a WAN to contact the target machines that will be set up in future guides.