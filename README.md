<h1 align="center">ARP Spoofing Defense Mechanism for a SDN Controller</h1>
<h3 align="center">A Mechanism deployed in a SDN controller to mitigate and prevent ARP spoofing attack in a SDN network</h3>
<h4 align="center">It's basically a demonstration of simulation using mininet</a></h3>

<h2 align="left">Tech Stack and Tools :</h2>
<p align="left">
<a href="https://www.python.org/" target="_blank" rel="noreferrer"> <img src="https://www.fullstackpython.com/img/logos/py.png" alt="react" width="180" height="100"/> </a>
<a href="https://mininet.org/" target="_blank" rel="noreferrer"> <img src="https://pradeepaphd.wordpress.com/wp-content/uploads/2016/07/contiki11.jpg?w=470" alt="tailwind" width="180" height="100"/> </a>
</p>

<h2 align="left">Workflow</h2>

![image](https://github.com/user-attachments/assets/dd7cb0f4-bd44-47c2-836b-b6959a3f95cb)



- **Add Job Application** :


- **List All Applications**:
All job applications are displayed by default on the homepage in a clean, organized, and responsive layout.

- **Filter Options**:
Users can filter applications **by Status** (e.g., only show "Interview" or "Offer") or **by Date of Application** Or apply both filters simultaneously for refined results.

- **Update Status**:
Users can update the status of any job application at any time.

- **Delete Application**:
Users can delete any job application entry with a single click.

- **Well-designed Interactive UI**:
The frontend is modern, responsive, and user-friendly, with interactive components for seamless experience.

- **Clean and Modular Code Structure**:
Backend follows MVC Architecture

- **RESTful APIs for robust and scalable development**

- Proper separation of concerns and reusable components

- Deployed on Front-end on **Vercel** and  Back-end on **Render**
  
- Leveraged usage of popular and efficient libraries including **Express, Mongoose, dotenv, CORS, and more**

- Used **MongoDB Cloud Database** for secure, scalable, and efficient data storage

<h2 align="left">Manual Project Installation</h2>
<h3>To get started with this project, clone the repository and install the necessary dependencies</h3>

```bash
# Clone the repository
git clone https://github.com/Rupesh2728/ARP-Spoofing-Defense-Mechanism-for-a-SDN-Controller.git

# Navigate to the project directory
cd ARP-Spoofing-Defense-Mechanism-for-a-SDN-Controller

# Setup the Mininet in Virtual box and place the "Topology.py" file inside root directory and "multi_switch_working_arp_detected.py" file inside "./mininet/mininet/forwarding"
# Use below commands
# Make sure to initialize the controller first and then topology

# Initialize the controller
./pox.py log.level --DEBUG proto.dhcpd --network=10.0.0.0/24 --ip=10.0.0.254 forwarding.l2_learning_arp_mitigation

# Initialize the Topology setup
sudo python Topology.py

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
  
- MongoDB Atlas account : **rupesh.p21@iiits.in**



