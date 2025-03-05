import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import nmap
import netifaces
from ipaddress import ip_network

# Global stop event for stopping scans
stop_event = threading.Event()

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
    if stop_event.is_set():
        return
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
        nm.scan(ip, str(port), arguments='-sV --version-all')
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
        nm.scan(hosts=network, arguments='-sn')
        total_hosts = len(nm.all_hosts())
        scanned = 0

        for host in nm.all_hosts():
            if stop_event.is_set():
                result_text.insert(tk.END, "Network scan stopped by user.\n")
                progress_var.set("Network scan stopped.")
                return
            scanned += 1
            hostname = nm[host].hostname() or "Unknown hostname"
            result_text.insert(tk.END, f"Active IP: {host} | Hostname: {hostname}\n")
            progress = (scanned / total_hosts) * 100
            progress_var.set(f"Network scan: %{progress:.2f}")
            root.update_idletasks()
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
            if stop_event.is_set():
                result_text.insert(tk.END, "Port scan stopped by user.\n")
                progress_var.set("Port scan stopped.")
                return
            scan_port(ip, port, result_dict)
            scanned_ports += 1
            progress = (scanned_ports / total_ports) * 100
            progress_var.set(f"Port scan: %{progress:.2f}")
            root.update_idletasks()

        for port, status in sorted(result_dict.items()):
            result_text.insert(tk.END, f"Port {port}: {status}\n")
        result_text.insert(tk.END, "Scan completed.\n")
        progress_var.set("Port scan completed.")

    threading.Thread(target=scan_worker, daemon=True).start()

# Start scan with GUI
def start_scan():
    stop_event.clear()  # Reset stop event
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
    stop_event.clear()  # Reset stop event
    network = network_entry.get()
    if not network:
        network = get_local_network()
        network_entry.delete(0, tk.END)
        network_entry.insert(0, network)
    threading.Thread(target=scan_network, args=(network, result_text, progress_var), daemon=True).start()

# Stop scan
def stop_scan():
    stop_event.set()

# Save results to file
def save_results():
    try:
        with open("scan_results.txt", "w") as f:
            f.write(result_text.get(1.0, tk.END))
        result_text.insert(tk.END, "Results saved to scan_results.txt\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error saving results: {e}\n")

# Create GUI
root = tk.Tk()
root.title("Advanced Port Scanner")
root.geometry("800x600")

# IP input
tk.Label(root, text="IP Address (For port scan):").grid(row=0, column=0, padx=10, pady=10, sticky="e")
ip_entry = tk.Entry(root, width=30)
ip_entry.grid(row=0, column=1, padx=10, pady=10)

# Port range input
tk.Label(root, text="Port Range (E.g., 1-100) (Blank = 0 - 65535):").grid(row=1, column=0, padx=10, pady=10, sticky="e")
port_entry = tk.Entry(root, width=30)
port_entry.grid(row=1, column=1, padx=10, pady=10)

# Network input
tk.Label(root, text="Network (Leave blank for auto):").grid(row=2, column=0, padx=10, pady=10, sticky="e")
network_entry = tk.Entry(root, width=30)
network_entry.grid(row=2, column=1, padx=10, pady=10)

# Scan buttons (Start Port Scan and Scan Network)
scan_button = tk.Button(root, text="Start Port Scan", command=start_scan)
scan_button.grid(row=3, column=0, padx=10, pady=10)

network_button = tk.Button(root, text="Scan Network", command=start_network_scan)
network_button.grid(row=3, column=1, padx=10, pady=10)

# Action buttons (Clear Results, Stop Scan, Save Results)
clear_button = tk.Button(root, text="Clear Results", command=lambda: result_text.delete(1.0, tk.END))
clear_button.grid(row=0, column=2, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan)
stop_button.grid(row=1, column=2, padx=10, pady=10)

save_button = tk.Button(root, text="Save Results", command=save_results)
save_button.grid(row=2, column=2, padx=10, pady=10)

# Progress status
progress_var = tk.StringVar()
progress_var.set("Waiting...")
progress_label = tk.Label(root, textvariable=progress_var)
progress_label.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

# Result area 
result_text = scrolledtext.ScrolledText(root, width=90, height=30, wrap=tk.WORD)
result_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Grid expandable
root.grid_rowconfigure(5, weight=1)
root.grid_columnconfigure(2, weight=1)

root.mainloop()