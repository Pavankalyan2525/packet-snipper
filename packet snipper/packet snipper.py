import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from scapy.all import *
import socket
import subprocess
import time
import threading
import queue

# Global variables
packet_queue = queue.Queue()
captured_packets = []
sniffer_thread = None
stop_sniffing_event = threading.Event()

# Function to get the domain name from an IP address
def get_domain_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip  # Return the IP if no domain name is found

# Function to extract domain names from DNS packets
def extract_domain_from_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        if packet[DNS].qd:  # Check if there is a question section
            qname = packet[DNS].qd.qname
            if qname:  # Ensure qname is not empty
                return qname.decode('utf-8').rstrip('.')
    return None

# Packet sniffer function
def packet_sniffer(interface, filter_string):
    while not stop_sniffing_event.is_set():
        sniff(prn=process_packet, iface=interface, filter=filter_string, store=0, timeout=1)
    stop_sniffing_event.clear()  # Reset the event

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Protocol mapping
        protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_names.get(protocol, "Unknown")

        # Extract domain name from DNS packets
        domain_name = extract_domain_from_dns(packet)

        if domain_name:
            packet_info = (
                f"Timestamp: {timestamp}, "
                f"Source: {src_ip}, "
                f"Destination: {domain_name} ({dst_ip}), "
                f"Protocol: {protocol_name}, "
                f"Info: {packet.summary()}\n"
            )
        else:
            # Show IP if not a DNS packet
            packet_info = (
                f"Timestamp: {timestamp}, "
                f"Source: {src_ip}, "
                f"Destination: {dst_ip}, "
                f"Protocol: {protocol_name}, "
                f"Info: {packet.summary()}\n"
            )

        # Add packet info to queue for processing
        packet_queue.put(packet_info)

        # Save packet for PCAPNG
        captured_packets.append(packet)

# Start sniffing in a separate thread
def start_sniffing(filter_selected):
    global sniffer_thread, stop_sniffing_event
    stop_sniffing_event.clear()  # Clear the event
    interface = get_wifi_interface()
    if not interface:
        messagebox.showerror("Error", "Wi-Fi interface not found!")
        return

    filter_string = "" if filter_selected == "All" else filter_selected
    sniffer_thread = threading.Thread(target=packet_sniffer, args=(interface, filter_string), daemon=True)
    sniffer_thread.start()

# Stop sniffing
def stop_sniffing():
    stop_sniffing_event.set()  # Signal to stop sniffing

# Process packets from the queue and update the GUI
def process_packets():
    while True:
        try:
            packet_info = packet_queue.get(timeout=1)
            captured_data_text.config(state=tk.NORMAL)
            captured_data_text.insert(tk.END, packet_info)
            captured_data_text.yview(tk.END)
            captured_data_text.config(state=tk.DISABLED)

            # Save to file
            with open("captured_packets.txt", "a") as file:
                file.write(packet_info)
        except queue.Empty:
            continue

# Save captured packets in PCAPNG format
def save_as_pcapng():
    if not captured_packets:
        messagebox.showwarning("Warning", "No packets captured to save.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".pcapng",
                                               filetypes=[("PCAPNG files", "*.pcapng"),
                                                          ("All files", "*.*")])
    if file_path:
        wrpcap(file_path, captured_packets)
        messagebox.showinfo("Saved", f"Captured packets saved as {file_path}.")

# Clear captured data and logs
def clear_data():
    global captured_packets
    captured_packets = []
    captured_data_text.config(state=tk.NORMAL)
    captured_data_text.delete(1.0, tk.END)
    captured_data_text.config(state=tk.DISABLED)

    # Clear the log file
    open("captured_packets.txt", "w").close()
    messagebox.showinfo("Cleared", "Captured data and logs have been cleared.")

# Function to get the Wi-Fi interface
def get_wifi_interface():
    try:
        output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
        for line in output.splitlines():
            if "Name" in line:
                return line.split(":")[1].strip()
    except subprocess.CalledProcessError:
        return None

# Create the GUI
def create_gui():
    global root, captured_data_text
    root = tk.Tk()
    root.title("Packet Sniffer")
    root.geometry("800x600")
    root.configure(bg="#2c3e50")

    # Header
    header_frame = tk.Frame(root, bg="#34495e", pady=10)
    header_frame.pack(fill=tk.X)
    title_label = tk.Label(header_frame, text="Network Packets Sniffer", fg="white", bg="#34495e", font=("Helvetica", 18, "bold"))
    title_label.pack()

    # Main Frame
    main_frame = tk.Frame(root, bg="#2c3e50")
    main_frame.pack(pady=20)

    # Filter Selection
    filter_frame = tk.Frame(main_frame, bg="#2c3e50")
    filter_frame.pack(pady=10)
    filter_label = tk.Label(filter_frame, text="Select Filter", fg="white", bg="#2c3e50", font=("Helvetica", 12))
    filter_label.pack(anchor=tk.W)

    filter_options = ["All", "tcp port 80", "tcp port 443", "udp", "icmp"]
    filter_listbox = tk.Listbox(filter_frame, height=5, bg="#34495e", fg="white", font=("Helvetica", 12), selectbackground="#1abc9c")
    for option in filter_options:
        filter_listbox.insert(tk.END, option)
    filter_listbox.pack(pady=5)

    # Buttons Frame
    buttons_frame = tk.Frame(main_frame, bg="#2c3e50")
    buttons_frame.pack(pady=20)
    button_style = {"bg": "#e74c3c", "fg": "white", "font": ("Helvetica", 12, "bold"), "width": 15}

    start_button = tk.Button(buttons_frame, text="Start Sniffing", command=lambda: start_sniffing(filter_listbox.get(tk.ACTIVE)), **button_style)
    start_button.grid(row=0, column=0, padx=10, pady=5)

    stop_button = tk.Button(buttons_frame, text="Stop Sniffing", command=stop_sniffing, **button_style)
    stop_button.grid(row=0, column=1, padx=10, pady=5)

    save_button = tk.Button(buttons_frame, text="Save as PCAPNG", command=save_as_pcapng, **button_style)
    save_button.grid(row=1, column=0, padx=10, pady=5)

    clear_button = tk.Button(buttons_frame, text="Clear Data", command=clear_data, **button_style)
    clear_button.grid(row=1, column=1, padx=10, pady=5)

    # Captured Data Display
    captured_data_frame = tk.Frame(main_frame, bg="#2c3e50")
    captured_data_frame.pack(pady=10)
    captured_data_label = tk.Label(captured_data_frame, text="Captured Data", fg="white", bg="#2c3e50", font=("Helvetica", 12))
    captured_data_label.pack(anchor=tk.W)

    captured_data_text = scrolledtext.ScrolledText(captured_data_frame, width=90, height=20, state=tk.DISABLED, bg="#34495e", fg="white", font=("Courier", 10))
    captured_data_text.pack(pady=10)

    # Start packet processing thread
    threading.Thread(target=process_packets, daemon=True).start()

    # Start the main loop
    root.mainloop()

# Run the GUI
if __name__ == "__main__":
    create_gui()
