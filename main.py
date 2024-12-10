import scapy.all as scapy
import threading
import tkinter as tk
from tkinter import scrolledtext

# Force Scapy to use WinPcap (or Npcap)
scapy.conf.use_pcap = True

# Packet counter and stop flag
packet_counter = 0
sniffing_running = False

# This function will process each captured packet
def process_packet(packet):
    global packet_counter
    packet_counter += 1
    
    # Print packet details to console (for debugging purposes)
    print(packet.show())

    # Display packet details in the GUI
    packet_info = f"Packet {packet_counter}: {packet.summary()}\n"
    output_text.insert(tk.END, packet_info)
    output_text.yview(tk.END)  # Auto-scroll to the latest packet

# This function will start the sniffing process
def start_sniffing():
    global sniffing_running
    sniffing_running = True
    packet_thread = threading.Thread(target=sniff_packets)
    packet_thread.daemon = True
    packet_thread.start()
    start_button.config(state=tk.DISABLED)  # Disable start button after starting
    stop_button.config(state=tk.NORMAL)    # Enable stop button

# This function will stop the sniffing process
def stop_sniffing():
    global sniffing_running
    sniffing_running = False
    start_button.config(state=tk.NORMAL)  # Enable start button again
    stop_button.config(state=tk.DISABLED) # Disable stop button after stopping

# This function runs the sniffing in a separate thread
def sniff_packets():
    global sniffing_running
    scapy.sniff(prn=process_packet, store=0, stop_filter=stop_filter, filter="ip")

# Stop condition for sniffing based on a flag
def stop_filter(packet):
    return not sniffing_running

# Setup the GUI
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("700x500")  # Set a fixed size for the window
root.resizable(False, False)  # Disable window resizing

# Set window icon (optional)
# root.iconbitmap('path_to_icon.ico')  # Uncomment and set the path to your icon file if desired

# Set a background color for the window
root.config(bg='#2C3E50')

# Create a Frame to hold widgets with padding and better layout
frame = tk.Frame(root, bg='#2C3E50')
frame.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

# Create a ScrolledText widget for output display
output_text = scrolledtext.ScrolledText(frame, width=80, height=20, font=("Arial", 10), wrap=tk.WORD)
output_text.pack(padx=5, pady=5)

# Create a title label with styling
title_label = tk.Label(frame, text="Packet Sniffer", font=("Arial", 16, "bold"), fg="white", bg="#2C3E50")
title_label.pack(pady=10)

# Create Start and Stop buttons with custom styles
start_button = tk.Button(frame, text="Start Sniffing", command=start_sniffing, width=20, height=1, font=("Arial", 12),
                         bg="#3498DB", fg="white", relief="solid", bd=2, activebackground="#2980B9")
start_button.pack(pady=5)

stop_button = tk.Button(frame, text="Stop Sniffing", command=stop_sniffing, width=20, height=1, font=("Arial", 12),
                        bg="#E74C3C", fg="white", relief="solid", bd=2, state=tk.DISABLED, activebackground="#C0392B")
stop_button.pack(pady=5)

# Start the GUI loop
root.mainloop()
