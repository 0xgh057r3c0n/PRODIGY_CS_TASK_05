# Packet Sniffer Tool (task5.py)

A simple Python-based packet sniffer tool built using `tkinter` for the GUI and `scapy` for packet capture and analysis. This tool captures network packets in real-time and allows users to inspect various packet details like source/destination IP, protocol, source/destination ports, and payload.

## Features

- **Capture and Display Network Packets**: Sniff and show packets in real-time.
- **Supports Common Protocols**: Captures packets for protocols like TCP, UDP, ICMP, and ARP.
- **Packet Details View**: View detailed packet information like source IP, destination IP, ports, protocol, and payload.
- **Intuitive GUI**: Simple interface with buttons to start/stop sniffing and clear the results.
- **Real-Time Updates**: Continuous display of network traffic with live updates.

## Requirements

- **Python 3.x**: Make sure Python 3 is installed on your system.
- **scapy**: Used for network packet capture and analysis.
- **tkinter**: Built-in Python module for creating the GUI.

### Install Dependencies

You can install the required dependencies using `pip`:

```bash
pip install scapy
```

`tkinter` should already be included with Python by default, so you don't need to install it separately.

## How to Use

1. **Run the Script**:
   Open a terminal or command prompt, navigate to the directory where `task5.py` is located, and run the script:
   
   ```bash
   python3 task5.py
   ```

2. **Start Sniffing**:
   - Press the **Start Sniffing** button to begin capturing network packets.
   - The packets will appear in the table with details like timestamp, source IP, destination IP, protocol, and more.

3. **Stop Sniffing**:
   - Press the **Stop Sniffing** button to stop capturing packets.

4. **Clear Results**:
   - Press the **Clear Results** button to clear the captured packets from the table.

5. **View Packet Details**:
   - Double-click on any packet entry in the table to view detailed information in the text area at the bottom.

## Supported Protocols

The tool captures the following types of packets:

- **TCP**: Transmission Control Protocol, typically used for web traffic, FTP, etc.
- **UDP**: User Datagram Protocol, used in applications like DNS, VoIP, etc.
- **ICMP**: Internet Control Message Protocol, used for ping and other diagnostic tools.
- **ARP**: Address Resolution Protocol, used for mapping IP addresses to MAC addresses.

## Notes

- **Permissions**: In order to capture network packets, the script may need to be run with administrator or root privileges, depending on your operating system.
- **Network Interface**: The tool will capture packets on all available interfaces. If you want to capture packets on a specific interface, you may need to modify the code to specify the interface.
- **Filter**: By default, the tool captures all IP and ARP packets. You can modify the packet filter in the code if you need to capture specific types of packets.

## Troubleshooting

- **No Packets Captured**: If you're not seeing any packets, ensure that your network interface is active and that you're running the script with the necessary permissions.
- **Scapy Issues**: If you're encountering issues with `scapy`, make sure it is properly installed and that your system's firewall is not blocking packet capture.

## License

This project is open-source and licensed under the MIT License.

## Author

- **0xgh057r3c0n** - [GitHub Profile]([https://github.com/0xgh057r3c0n]
