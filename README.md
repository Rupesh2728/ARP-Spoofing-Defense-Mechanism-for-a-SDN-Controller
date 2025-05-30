<h1 align="center">ARP Spoofing Defense Mechanism for a SDN Controller</h1>
<h3 align="center">A Mechanism deployed in a SDN controller to mitigate and prevent ARP spoofing attack in a SDN network</h3>
<h4 align="center">It's basically a demonstration of simulation using mininet</a></h3>

<h2 align="left">Tech Stack and Tools :</h2>
<p align="left">
<a href="https://www.python.org/" target="_blank" rel="noreferrer"> <img src="https://www.fullstackpython.com/img/logos/py.png" alt="react" width="180" height="100"/> </a>
<a href="https://mininet.org/" target="_blank" rel="noreferrer"> <img src="https://pradeepaphd.wordpress.com/wp-content/uploads/2016/07/contiki11.jpg?w=470" alt="tailwind" width="180" height="100"/> </a>
</p>

<h2 align="left">Workflow</h2>

![image](https://github.com/user-attachments/assets/55607890-72ce-4871-a403-1910785ff553)

- **Switch Initialization** : The process starts when a new switch is connected, triggering ARP Spoof Detection instance creation.

- **Three Concurrent Processes**: Upon instance creation, three parallel activities begin,
  1.) Periodic Maintenance (cleans stale entries and updates global tables)
  2.) Topology Discovery (sends discovery packets and identifies switch links)
  3.) Packet Handling (monitors incoming packets)
  
- **Packet Type Analysis:**:
Incoming packets are classified into three types: IP Packets, ARP Requests, and ARP Replies, each following a different processing path.

- **IP Packet Handling:**:
  1.) Forwarded to IP Packet Forwarding
  2.) Processed through L2 Learning Switch Logic
  3.) Then checked for known destination to decide between Inter-Switch Routing, Direct Port Forwarding, or Controlled Flood.

- **ARP Request Handling**:
 1.) Checked against the Global Host Table
 2.) Known destinations are Targeted Forwarded
 3.) Unknown destinations trigger a Controlled Flood
  
- **ARP Reply Verification**:
  1.) Passed through Spoofing Detection
  2.) If spoofing is detected, the system flags it as a Potential Spoof.

- **Spoof Response Mechanism:**
  1.) The spoofing MAC address is Blocked,
  2.) Added to a Global Blacklist
  3.) And Blocked on All Switches for security enforcement.
  
- **Dynamic Topology Awareness**:
  By identifying switch links through discovery packets, the system maintains an up-to-date view of network topology for accurate packet routing and spoof detection.**

- **Global State Updates** : Periodic updates ensure stale data is removed and global tables reflect the most recent network state, supporting efficient and secure packet routing.

<h2 align="left">Manual Project Installation and Testing</h2>
<h3>To get started with and run this project, clone the repository and install the necessary dependencies</h3>

```bash
# Clone the repository
git clone https://github.com/Rupesh2728/ARP-Spoofing-Defense-Mechanism-for-a-SDN-Controller.git

# Navigate to the project directory
cd ARP-Spoofing-Defense-Mechanism-for-a-SDN-Controller

# Setup the Mininet in Virtual box and place the "Topology.py" file inside root directory and "multi_switch_working_arp_detected.py" file inside "./pox/pox/forwarding"
# Use below commands
# Make sure to initialize the controller first and then topology

# Initialize the controller and create a file named "l2_learning_arp_mitigation" and paste the code in the file "multi_switch_working_arp_detected.py" into newly created file
./pox.py log.level --DEBUG proto.dhcpd --network=10.0.0.0/24 --ip=10.0.0.254 forwarding.l2_learning_arp_mitigation

# Initialize the Topology setup
sudo python Topology_Code_ARP_Detected.py

# Make sure to check controller and Topology are connected
# For e.g
h11 ping h12

# Testing ARP Spoofing defence
h12 ping h31 &
h11 arp -s 10.0.0.7 00:00:00:00:00:01
h11 python -c "from scapy.all import *; send(ARP(op=2, pdst='10.0.0.2', psrc='10.0.0.7', hwsrc='00:00:00:00:00:01', hwdst='00:00:00:00:00:02'"
```

<h2 align="left">Demonstration Video</h2>

https://github.com/user-attachments/assets/d9dddcf5-4ca4-4ae8-840e-f04723fd1295


<h2 align="left">Contact Me</h2>

- 📫 You can to reach me by mailing to **rupesh.p21@iiits.in** or **rupeshprofessional2728@gmail.com**

- 👨‍💻 Project is available at [https://github.com/Rupesh2728/ARP-Spoofing-Defense-Mechanism-for-a-SDN-Controller.git]

- Please also visit the report attached for better understanding
  
- MongoDB Atlas account : **rupesh.p21@iiits.in**



