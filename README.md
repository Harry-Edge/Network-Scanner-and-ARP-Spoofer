# Network-Scanner-and-ARP-Spoofer
Scans current network and allows the user to commit an ARP spoof off the results 

## General info
A terminal program that can perform multiple scans to detect devices connected to the network. The scan result will display the name, IP, and MAC address of each device.

After the scan, the user can then perform an ARP spoof on the target to become the Man-in-the-Middle.

Recommended to use Sudo when running on MAC or running as admin on Windows to avoid issues.


## Packet Forwarding 
By default, the program will automatically forward packets to the target device. This will allow the internet connection to be uninterrupted on the target device. Currently this will only work on macOS.

If running on another os, the below lines of codes will need to be removed.

Line 102

```
subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"])
```

line 128

```
subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=0"])
```

After that, make sure you manually enable packet forwarding on your respective os. Alternatively, keep it disabled if you want to halt the internet connection on the victim's device. 