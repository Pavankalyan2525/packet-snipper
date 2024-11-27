# packet-sniper
This is a simple Packet Sniffer developed using Python. The tool allows you to capture and analyze network packets in real-time. It uses libraries like scapy for packet manipulation and socket for network communication. The packet sniffer can be used for educational purposes to monitor and inspect network traffic.

Features
Capture packets: The sniffer captures various types of network packets, such as TCP, UDP, and ICMP.
Packet analysis: The tool displays basic packet information like source IP, destination IP, protocol type, and payload.
Real-time monitoring: The sniffer provides real-time packet capture with continuous packet display.
Filter packets: Filters can be applied to capture specific types of traffic (e.g., only TCP traffic or traffic from a specific IP address).

**Prerequisites**
Python 3.x
Required Python Libraries:
scapy: For packet capture and analysis.
socket: For networking functionalities.
To install the required libraries, run the following command:
**pip install scapy**

**Usage**
Clone or download the repository to your local machine:
git clone https://github.com/your-username/packet-sniffer.git

**Run the script:**
go to dist folder and there to find the exe file of packet sniffer
Double click on **packetsniffer.exe** to run the exe file
**or**
run the exe file using command prompt :
cd "C:\path\to\your\folder\packetsniffer.exe"

The sniffer will start capturing packets and display their details in the terminal. You can stop the capture anytime by clicking at stop packets
Save the capturing in PCAPNG Format at your specific file path.
Clear packets by using clear packet.


Optionally, you can add custom filters by modifying the packetsniffer.py script.

