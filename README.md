# 🕵️‍♂️ Packet Sniffer  

A simple Python-based packet sniffer that captures and analyzes network packets. It logs source and destination IPs, protocols, and payloads.  

## 🚨 Ethical Disclaimer  
This tool is for **educational purposes only**. Unauthorized network monitoring is **illegal**. Ensure you have proper permissions before use.  

## 🔥 Features  
✅ Captures network packets in real-time  
✅ Displays source and destination IPs  
✅ Supports TCP, UDP filtering  
✅ Saves logs to a file  
✅ Uses command-line arguments for flexibility  

## 📥 Installation  

1. **Clone the repository:**  
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   
2.Install dependencies:


pip install -r requirements.txt

3.Run the sniffer:


sudo python packet_sniffer.py -i wlan0 -o logs.txt -f "tcp"
-i wlan0 → Network interface (replace with yours)

-o logs.txt → Log file to save packets

-f "tcp" → (Optional) Filter for TCP packets
