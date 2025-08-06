from scapy.all import sniff, get_if_list, Raw
from scapy.layers.inet import IP

def list_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"  {idx}: {iface}")
    return interfaces

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = ip_layer.proto
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")

        print(f"\n[+] {ip_layer.src} -> {ip_layer.dst} | Protocol: {protocol}")

        if Raw in packet:
            try:
                payload = packet[Raw].load
                print(f"    Payload: {payload[:50]}")
            except:
                print("    [!] Payload could not be decoded")

if __name__ == "__main__":
    interfaces = list_interfaces()
    choice = int(input("Enter the interface number to sniff on: "))
    selected_iface = interfaces[choice]

    print(f"[*] Starting capture on interface: {selected_iface}")
    sniff(filter="ip", prn=process_packet, store=0, iface=selected_iface)
