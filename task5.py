import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Raw
from datetime import datetime
import threading
import queue

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer Tool by 0xgh057r3c0n")
        self.root.geometry("900x600")
        self.root.config(bg="#2b3d3d")
        
        # Banner and version details
        self.banner_frame = tk.Frame(root, bg="#4d4d4d")
        self.banner_frame.pack(fill=tk.X, pady=5)
        self.banner_label = tk.Label(
            self.banner_frame, text="Packet Sniffer Tool v1.0 by 0xgh057r3c0n",
            bg="#4d4d4d", fg="white", font=("Arial", 12, "bold")
        )
        self.banner_label.pack()

        # Packet display table
        columns = ("Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Payload")
        self.packet_tree = ttk.Treeview(root, columns=columns, show="headings", height=15)
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100, anchor="w")
        self.packet_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scrolled text area for viewing selected packet details
        self.details_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#1e1e1e", fg="white", height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Control buttons
        button_frame = tk.Frame(root, bg="#2b3d3d")
        button_frame.pack(pady=5)
        tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing, bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="#f44336", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Clear Results", command=self.clear_results, bg="#ff9800", fg="white").pack(side=tk.LEFT, padx=5)

        # Event binding for selecting packets
        self.packet_tree.bind("<Double-1>", self.display_packet_details)

        # Packet queue
        self.packet_queue = queue.Queue()
        self.sniffing = False
        self.sniffer_thread = None

        # Periodic check for new packets in the queue
        self.root.after(100, self.process_packet_queue)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.clear_results()
            self.sniffer_thread = threading.Thread(target=self.capture_packets)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join()

    def capture_packets(self):
        # Capture all IP and ARP packets to cover common protocols (TCP, UDP, ICMP, ARP, etc.)
        sniff(prn=self.packet_callback, store=False, filter="ip or arp", stop_filter=lambda x: not self.sniffing)

    def packet_callback(self, packet):
        self.packet_queue.put(packet)

    def process_packet_queue(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.display_packet(packet)
        self.root.after(100, self.process_packet_queue)

    def display_packet(self, packet):
        packet_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = dst_ip = src_port = dst_port = protocol_name = payload_data = "N/A"

        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            # Check for specific protocols and set the protocol name
            if protocol == 6:  # TCP
                protocol_name = "TCP"
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                if Raw in packet:
                    payload_data = self.decode_payload(packet[Raw].load)
            elif protocol == 17:  # UDP
                protocol_name = "UDP"
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                if Raw in packet:
                    payload_data = self.decode_payload(packet[Raw].load)
            elif protocol == 1:  # ICMP
                protocol_name = "ICMP"
                if Raw in packet:
                    payload_data = self.decode_payload(packet[Raw].load)
        elif ARP in packet:
            protocol_name = "ARP"
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst

        # Insert data into the Treeview
        self.packet_tree.insert("", "end", values=(packet_time, src_ip, dst_ip, protocol_name, src_port, dst_port, payload_data))

    def decode_payload(self, payload):
        try:
            return payload.decode('utf-8', errors='ignore')
        except Exception:
            return str(payload)

    def display_packet_details(self, event):
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return
        
        packet_data = self.packet_tree.item(selected_item)["values"]
        details = (
            f"Timestamp: {packet_data[0]}\n"
            f"Source IP: {packet_data[1]}\n"
            f"Destination IP: {packet_data[2]}\n"
            f"Protocol: {packet_data[3]}\n"
            f"Source Port: {packet_data[4]}\n"
            f"Destination Port: {packet_data[5]}\n"
            f"Payload:\n{packet_data[6]}"
        )
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)

    def clear_results(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
