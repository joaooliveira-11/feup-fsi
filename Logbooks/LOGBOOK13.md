# Packet Sniffing and Spoofing Lab

# Lab Task Set 1: Using Scapy to Sniff and Spoof Packets

## Context
Many tools can be used to do sniffing and spoofing, but most of them only provide fixed functionalities. Scapy is different: it can be used not only as a tool, but also as a building block to construct other sniffing and spoofing tools, i.e., we can integrate the Scapy functionalities into our own program. In this set of tasks, we will use Scapy for each task.

# Task 1.1: Sniffing Packets

## Context

The objective of this task is to learn how to use Scapy to do packet sniffing in Python programs.

Using the following python code, we will sniff the packets on the br-c93733e9f913 interface.:
```
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
pkt.show()
pkt = sniff(iface=’br-c93733e9f913’, filter=’icmp’, prn=print_pkt)
```

We need to find the name of the corresponding network interface on our VM, because we need to use it in our programs. The interface name is the concatenation of br- and the ID of the network created by Docker. When we use ifconfig to list network interfaces, we will see quite a few. Look for the IP address 10.9.0.1.

![interface_name](../docs/logbook13/information.png)

## Task 1.1A Solution

By running this python script on the attacker with root:

```python
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-cf370a106790', filter='icmp', prn=print_pkt)
```

![python_script_task1.1](../docs/logbook13/python_script_task1.1.png)

And then using ping on hostA to hostB:
![ping_containerB](../docs/logbook13/ping_containerB.png)

We can see that our attack was successful because the packets were intercepted:
![packet_interception](../docs/logbook13/packet_interception.png)


When running without root, we got the following error:
![error](../docs/logbook13/running_without_root_Task1.png)


## Task 1.1B

Usually, when we sniff packets, we are only interested certain types of packets. We can do that by setting filters in sniffing. Scapy’s filter use the BPF (Berkeley Packet Filter) syntax.

• To capture only the ICMP packet, we use the following code (The same used in the Task 1.1 A):

```python
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-cf370a106790', filter='icmp', prn=print_pkt)
```

• To capture any TCP packet that comes from a particular IP and with a destination port number 23.

```python
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-cf370a106790', filter='tcp and src host <source_ip> and dst port 23', prn=print_pkt)
```

• To capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to.

```python
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-cf370a106790', filter='net 128.230.0.0/16', prn=print_pkt)
```

# Task 1.2: Spoofing ICMP Packets




