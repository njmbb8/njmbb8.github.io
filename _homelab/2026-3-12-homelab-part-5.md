---
title: "Virtual Active Directory Lab for Pentest Practice Part Five: Creating the SIEM and Connecting an Agent"
author: "Nate McGraw"
layout: default
---

I want to be able to see what's going on from the defender's standpoint when I attack the network, so I'm adding a SIEM which will live in the management subnet with collectors in the DMZ and the internal subnets which will require more firewall rules to support. The first step is to create an Ubuntu VM to install Wazuh on.

# Creating an Ubuntu VM

I used Ubuntu Server 24.04 which is the latest version that the Wazuh docs say is supported. I gave the VM resources according to the table provided in the Wazuh [quickstart](https://documentation.wazuh.com/current/quickstart.html).

| Agents |   CPU  |  RAM | Storage (90 days) |
|--------|:------:|:----:|-------------------|
| 1-25   | 4 vCPU | 8 GB | 50 GB             |
| 25-50  | 8 vCPU | 8 GB | 100 GB            |
| 50-100 | 8 vCPU | 8 GB | 200 GB            |

Ubuntu defaulted to only allotting half of the storage to leave space for restore points to be stored, but I'm going to keep my own backups and I want all the space for the SIEM, so I gave all available space to the LVM.

![](/assets/img/ad_lab/part_five/ubuntu_storage.png)

I'm planning on 3 Agents at the moment and definitely nowhere close to 25, so I'm going with the minimum. During installation, I gave the machine a static IP address of 192.168.100.25. When I came to the Ubuntu archive mirror configuration, All hosts failed to resolve as no rules had been created to allow the traffic.

# Creating Firewall Rules to Support the SIEM's Traffic

The SIEM is the only device on the mgmt network, so I made rules targeting its static IP specifically. If I don't have a need for other devices to access the WAN, I'm not going to create a rule for it. I allowed HTTP, HTTPS, and DNS traffic which was enough to get the Ubuntu machine up and running.

![](/assets/img/ad_lab/part_five/mgmt_fw_rules.png)

I also created a floating rule which allowed traffic from the DMX or the internal AD network to the SIEM over TCP port 1514-1515 to allow for the actual log collection.

# Installing Wazuh AIO

Going back to the [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html), the installation instructions are very simple: run `curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`. This took a while to run, but once it finished, I was provided with access instructions for the Wazuh Web UI.

![](/assets/img/ad_lab/part_five/wazuh_instructions.png)

Opening https://192.168.100.25/ from the host while connected to the management VPN gives me a Wazuh login screen where I was able to log in with the provided credentials and then change the admin account's password. That's it, Wazuh is set up and ready to receive logs.

# Deploying a New Agent

Wazuh makes deploying agents super easy too. I clicked the "Deploy an Agent" button and filled in info about the target (the DC will be the first agent) and was provided with a PowerShell one-liner to install the agent and begin collection.
After starting the WazuhSvc service, I can see the agent show up in the web interface. 

![](/assets/img/ad_lab/part_five/connected_agent.png)