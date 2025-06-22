from scapy.all import *
from pyfiglet import Figlet
from colorama import Fore, Style, init


# Create the banner
figlet = Figlet(font='slant')  # You can change font to 'block', 'big', 'standard', etc.
banner = figlet.renderText('Packet Sniffer')

# Print with color
print(Fore.RED + banner + Style.RESET_ALL)

anotherOp= True
while (anotherOp==True):
    print("=============================================")
    print("Enter 1 to sniff packets")
    print("Enter 2 to read a pcap file\n")
    mode = int(input())


    if mode == 1:
        print(f"Select interface({get_if_list()}): ")
        interface = input()
        print (f"Enter no. of packets (0 if no limit): ")
        packetscount = int(input())
        print ("Specific filter? (Y/N): ")
        filterQ = input()
        if filterQ == 'Y'or filterQ =='y':
            print("Type the filter you want to apply: ")
            inputfilter = input()
        else: inputfilter = None
        packets= sniff(iface= interface, count= packetscount, filter= inputfilter )
        i= 1
        
        for packet in packets:
            print(f"Packet no. {i}\n")
            i+=1
            packet.show()
            print("--------------------------------------------------------")
        print("Do you want summary?(Y/N): ")
        summary = input()
        if summary=='Y'or summary=='y':
            print(packets.summary())
        print("Do you want to do another operation?(Y/N): ")
        anotherOp = input()
        if anotherOp=='Y'or anotherOp=='y':
            anotherOp = True
        else: anotherOp= False


    elif mode == 2:
        print("Enter relative path to file: ")
        filepath = input().strip()
        pcapfile = rdpcap(filepath)

        print("Apply Filter? (Y/N)")
        fil = input().strip().lower()

        if fil == 'y':
            # 1. Protocol Filter
            inputprotocol = input("Enter Protocol (TCP/UDP) or 0 for no filter: ").strip().upper()
            if inputprotocol == 'TCP':
                pcapfile = [pkt for pkt in pcapfile if TCP in pkt]
                proto_layer = TCP
            elif inputprotocol == 'UDP':
                pcapfile = [pkt for pkt in pcapfile if UDP in pkt]
                proto_layer = UDP
            else:
                proto_layer = None  # No protocol filter

            # 2. Port Filter
            inputport = input("Enter sport/dport (or 0 for no filter): ").strip().lower()
            if inputport in ['sport', 'dport'] and proto_layer:
                try:
                    portno = int(input("Enter port number: ").strip())
                    if inputport == 'sport':
                        pcapfile = [pkt for pkt in pcapfile if proto_layer in pkt and pkt[proto_layer].sport == portno]
                    else:
                        pcapfile = [pkt for pkt in pcapfile if proto_layer in pkt and pkt[proto_layer].dport == portno]
                except ValueError:
                    print("Invalid port number, skipping port filter.")

            # 3. IP Filter
            inputiptype = input("Enter srcIP/dstIP (or 0 for no filter): ").strip().lower()
            if inputiptype in ["srcip", "dstip"]:
                inputip = input("Enter IP address: ").strip()
                if inputiptype == "srcip":
                    pcapfile = [pkt for pkt in pcapfile if IP in pkt and pkt[IP].src == inputip]
                elif inputiptype == "dstip":
                    pcapfile = [pkt for pkt in pcapfile if IP in pkt and pkt[IP].dst == inputip]

        # 4. Print Packets
        for i, pkt in enumerate(pcapfile, 1):
            print(f"\nPacket no. {i}")
            pkt.show()
            print("--------------------------------------------------------")



        continue    

