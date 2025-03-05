import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import nmap
import netifaces
from ipaddress import ip_network

# Automatically detect the user's local network
def get_local_network():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        interface = gateways['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        network = ip_network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        return f"Error: Local network could not be detected ({e})"

# Port scanning function
def scan_port(ip, port, result_dict):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = get_service(ip, port)
            result_dict[port] = f"Open - {service}"
        sock.close()
    except:
        pass

# Service and version detection
def get_service(ip, port):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, str(port), arguments='-sV --version-all')  # More detailed service detection
        if ip in nm.all_hosts() and str(port) in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port]['name']
            version = nm[ip]['tcp'][port]['version']
            return f"{service} ({version})" if version else service
        return "Unknown service"
    except nmap.PortScannerError as e:
        return f"Service detection failed ({e})"
    except:
        return "Unknown service"

# Scan IPs on the network (with percentage and hostname)
def scan_network(network, result_text, progress_var):
    nm = nmap.PortScanner()
    try:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Scanning network: {network}\n")
        nm.scan(hosts=network, arguments='-sn')  # Find active devices only
        total_hosts = len(nm.all_hosts())
        scanned = 0

        for host in nm.all_hosts():
            scanned += 1
            hostname = nm[host].hostname() or "Unknown hostname"
            result_text.insert(tk.END, f"Active IP: {host} | Hostname: {hostname}\n")
            progress = (scanned / total_hosts) * 100
            progress_var.set(f"Network scan: %{progress:.2f}")
            root.update_idletasks()  # Update the GUI
        result_text.insert(tk.END, "Network scan completed.\n")
        progress_var.set("Network scan completed.")
    except nmap.PortScannerError as e:
        result_text.insert(tk.END, f"Error: Nmap scan failed ({e}).\n")
    except Exception as e:
        result_text.insert(tk.END, f"Unknown error: {e}\n")

# Port scanning (with percentage)
def start_port_scan(ip, start_port, end_port, result_text, progress_var):
    result_dict = {}
    total_ports = end_port - start_port + 1
    scanned_ports = 0

    def scan_worker():
        nonlocal scanned_ports
        for port in range(start_port, end_port + 1):
            scan_port(ip, port, result_dict)
            scanned_ports += 1
            progress = (scanned_ports / total_ports) * 100
            progress_var.set(f"Port scan: %{progress:.2f}")
            root.update_idletasks()

        # Display results after scanning
        for port, status in sorted(result_dict.items()):
            result_text.insert(tk.END, f"Port {port}: {status}\n")
        result_text.insert(tk.END, "Scan completed.\n")
        progress_var.set("Port scan completed.")

    # Start the scanning process in a separate thread
    threading.Thread(target=scan_worker, daemon=True).start()

# Start scan with GUI
def start_scan():
    ip = ip_entry.get()
    port_range = port_entry.get()

    if port_range:
        try:
            start_port, end_port = map(int, port_range.split('-'))
        except:
            result_text.insert(tk.END, "Invalid port range! Example: 1-100\n")
            return
    else:
        start_port, end_port = 1, 65535

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scan started: {ip} ({start_port}-{end_port})\n")
    start_port_scan(ip, start_port, end_port, result_text, progress_var)

# Start network scan
def start_network_scan():
    network = network_entry.get()
    if not network:
        network = get_local_network()
        network_entry.delete(0, tk.END)
        network_entry.insert(0, network)
    threading.Thread(target=scan_network, args=(network, result_text, progress_var), daemon=True).start()

# Create GUI
root = tk.Tk()
root.title("Port Scanner")
root.geometry("600x450")

# IP input
tk.Label(root, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

# Port range input
tk.Label(root, text="Port Range (e.g., 1-100)(leave blank to scan all ports):").grid(row=1, column=0, padx=5, pady=5)
port_entry = tk.Entry(root)
port_entry.grid(row=1, column=1, padx=5, pady=5)

# Network input
tk.Label(root, text="Network (leave blank for auto):").grid(row=2, column=0, padx=5, pady=5)
network_entry = tk.Entry(root)
network_entry.grid(row=2, column=1, padx=5, pady=5)

# Scan buttons
scan_button = tk.Button(root, text="Start Port Scan", command=start_scan)
scan_button.grid(row=3, column=0, padx=5, pady=5)

network_button = tk.Button(root, text="Scan Network", command=start_network_scan)
network_button.grid(row=3, column=1, padx=5, pady=5)

# Progress status
progress_var = tk.StringVar()
progress_var.set("Waiting...")
progress_label = tk.Label(root, textvariable=progress_var)
progress_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Result area
result_text = scrolledtext.ScrolledText(root, width=70, height=20)
result_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()