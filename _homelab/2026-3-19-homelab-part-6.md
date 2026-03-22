---
title: "Virtual Active Directory Lab for Pentest Practice Part Six: Collecting Logs from the Firewall"
author: "Nate McGraw"
layout: default
---

- [Installing and Configuring the Plugin](#installing-and-configuring-the-plugin)
- [Configuring Suricata](#configuring-suricata)
- [Detecting an Nmap Scan](#detecting-an-nmap-scan)


I want the Wazuh SIEM to be able to detect and monitor network traffic as well which will give visibility into techniques like port scanning and DNS poisoning. Fortunately, there is a Wazuh agent plugin available for OPNSense which is available to install.

# Installing and Configuring the Plugin

I installed the plugin by opening the OPNSense Web UI and then clicking System ⇒ Firmware ⇒ Plugins, checking the box for community plugins and searching `os-wazuh-agent`. Once it was done, I needed to reboot to see the Wazuh Agent section in Services.

In the settings section, I set the "Manager hostname" value to the Wazuh VM's IP address so that the collection could happen. As for the applications, this is where the agent will collect logs from, so I need to figure out what is important to be monitored. Dnsmasq is an easy choice to see DNS and DHCP traffic and my initial inclination was to add the filter or firewall applications, but this would be way too resource intensive, especially for a virtual environment. Instead, I selected suricata so that I can have Suricata act as an IDS which will analyze the traffic and send alerts to Wazuh when they are important rather than sending all of the logs to the SIEM.

With this configuration in place, I clicked Apply and another agent showed up in Wazuh.

![](/assets/img/ad_lab/part_six/new_agent.png)

# Configuring Suricata

Suricata is included in OPNSense by default, so the installation step has already been done for me. Clicking administration under the Intrusion Detection section of services in the sidebar brings me to the Suricata configuration page.

The first step is to enable the IDS by checking the bx for "Enabled". I don't want my intrusion attempts being prevented just yet, so I left the capture mode in "PCAP live mode (IDS)" and made sure that promiscuous mode was enabled so that all traffic could be monitored. I then changed the pattern matcher to Hyperscan which should help with speed and performance, but I can always change it later if resources start running short.

I really only want logs for the DMZ and internal network, so I removed the WAN from the list of selected interfaces and added the DMZ and internal interfaces. In order to detect intrusion, the IDS needs to know what boundaries need to be crossed to be considered an intrusion. This is where the "Home networks" field comes in. Switching on the toggle for advanced mode shows the relevant setting which is already populated with the standard class A, B, and C IP ranges. I deleted the class A range(10.0.0.0/8) and replaced it with the internal network IP range(10.0.3.0/24) and the DMZ IP range(10.0.2.0/24).

The last setting that needs to be changed is to check the box for "Enable eve syslog output". The Wazuh agent monitors the syslog for events, so the alerts need to be sent there for Wazuh to pick up on them.

# Detecting an Nmap Scan

Suricata does not come with many useful rules by default. Rules can be added by going to the "Download" tab. I'm grabbing ET open/emergin-scan as I want to detect an Nmap scan as a proof of concept. 

After enabling the rule, I went to the Kali VM and ran `nmap -f -sV 10.0.3.2` which should be plenty noisy for a detection(going to the rules tab shows that there is a rule specifically for this command). 

![](/assets/img/ad_lab/part_six/successful_detection.png)

It works! Suricata is detecting the Nmap scan using the enabled rules and Wazuh is getting the alerts, how exciting! Now I can see the detectability of my attacks and tune my methodology accordingly.