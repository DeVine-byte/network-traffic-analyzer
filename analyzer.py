import pyshark
import dpkt
import re
import pandas as pd
import matplotlib.pyplot as plt

#function to capture traffic
def capture(interface, traffic_count):

#store captured traffic
	packets = []
#attempt capture
	try:
		traffic = pyshark.LiveCapture(interface=interface, include_raw=True, use_json=True)
		print(f"[+]Starting capture on {interface} interface...\n")
		for packet in traffic.sniff_continuously(packet_count=traffic_count):
			packets.append(packet)
			print(f'Captured packet: Time: {packet.sniff_time}, Source: {packet.ip.src}, Destination: {packet.ip.dst}, Protocol: {packet.highest_layer}')

	except Exception as e:
		print(f'error: {e}')
	
	return packets

#decode traffic for analysis
def decode_traffic(captured_traffic):

	print("Decoding...")
#store decoded traffic
	decode_packet = []

#decode each packet captured
	for packet in captured_traffic:
#turn captured trafic to bytes
		decode_traffic = packet.get_raw_packet()
#attempt decode

		try:
			decoded = dpkt.ethernet.Ethernet(decode_traffic)
			decode_packet.append(decoded)
		except Exception as e:
			print(f"{e}: Unable to decode Packet")
	
	return decode_packet


#To make address readable

def format(byte):
	mac_str = ':'.join(f'{b:02x}' for b in byte)
	return mac_str

def show(decoded_packets):
# Protocol Distribution Analysis

	protocol_counts = {}
	tcp_ports = {}
	udp_ports = {}

	for packet in decoded_packets:
		if isinstance(packet, dpkt.ethernet.Ethernet):
			if isinstance(packet.data, dpkt.ip.IP):
				protocol = packet.data.__class__.__name__
				protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

				                # Check for TCP or UDP
				if isinstance(packet.data.data, dpkt.tcp.TCP):
					src_port = packet.data.data.sport
					dst_port = packet.data.data.dport
					tcp_ports[packet.data.src] = tcp_ports.get(packet.data.src, 0) + 1
					tcp_ports[packet.data.dst] = tcp_ports.get(packet.data.dst, 0) + 1
				elif isinstance(packet.data.data, dpkt.udp.UDP):
					src_port = packet.data.data.sport
					dst_port = packet.data.data.dport
					udp_ports[packet.data.src] = udp_ports.get(packet.data.src, 0) + 1
					udp_ports[packet.data.dst] = udp_ports.get(packet.data.dst, 0) + 1

				# check ARP
			elif isinstance(packet.data, dpkt.arp.ARP):
				protocol_counts['ARP'] = protocol_counts.get('ARP', 0) + 1
				src_mac = format(packet.data.sha)
				dst_mac = format(packet.data.tha)
				print(f'ARP Packet: Source MAC: {src_mac}, Destination MAC: {dst_mac}')

			else:
				print(f"Non-IP Packet: {packet.data.__class__.__name__}")


	protocol_df = pd.DataFrame(list(protocol_counts.items()), columns=['Protocol', 'Count'])
	protocol_df.plot(kind='bar', x='Protocol', y='Count')
	plt.title('Protocol Distribution')
	plt.savefig('protocol_distribution.png')

	# Packet Size Distribution Analysis
	packet_sizes = [len(packet) for packet in decoded_packets]
	packet_size_categories = pd.cut(packet_sizes, bins=[0, 100, 500, 1500, float('inf')], labels=['<100', '100-500', '500-1500', '>1500'])
	packet_size_counts = packet_size_categories.value_counts()
	packet_size_counts.plot(kind='hist')
	plt.title('Packet Size Distribution')
	plt.savefig('packet_size_distribution.png')

	top_tcp_talkers = sorted(tcp_ports.items(), key=lambda x: x[1], reverse=True)[:10]
	top_udp_talkers = sorted(udp_ports.items(), key=lambda x: x[1], reverse=True)[:10]

	print('Top TCP Talkers:')
	for mac, count in top_tcp_talkers:
		print(f'MAC: {format(mac)}, Count: {count}')
	        
	print('Top UDP Talkers:')
	for mac, count in top_udp_talkers:
		print(f'MAC: {format(mac)}, Count: {count}')

network = input("[+]Enter Network Interface: ")
traffic_count = 50

start = capture(network, traffic_count)
analyze = decode_traffic(start)

for packet in analyze:
	source = packet.src
	source = format(source)
	destination = packet.dst
	destination = format(destination)
	print("source: ", source)
	print("destination: ", destination)
	packet_type = packet.type
	if packet_type == 2048:
		print("Type: IPv4")
	elif packet_type == 2054:
		print("Type: ARP")
	else:
		print("Type: ", packet.type)
show(analyze)
