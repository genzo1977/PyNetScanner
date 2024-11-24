import tkinter as tk
from tkinter import ttk
from ipaddress import ip_network
from pythonping import ping
import threading

# Flag to control the scanning process
cancel_scan = False

def scan():
    global cancel_scan
    cancel_scan = False
    scan_button.config(state=tk.DISABLED, text="Scanning...")
    cancel_button.config(state=tk.NORMAL)
    results_listbox.delete(0, tk.END)
    progress_bar["value"] = 0

    network_addr = network_var.get()

    try:
        network = ip_network(network_addr, strict=False)
    except ValueError:
        results_listbox.insert(tk.END, "Invalid network address!")
        scan_button.config(state=tk.NORMAL, text="Scan")
        cancel_button.config(state=tk.DISABLED)
        return

    total_hosts = len(list(network.hosts()))
    progress_step = 100 / total_hosts

    def run_scan():
        global cancel_scan
        for index, ip in enumerate(network.hosts(), start=1):
            if cancel_scan:
                results_listbox.insert(tk.END, "Scan cancelled!")
                break
            root.update()
            ip = str(ip)
            response = ping(ip, count=1, timeout=1, verbose=False)
            if response.success():
                results_listbox.insert(tk.END, f"IP: {ip} is online")
            progress_bar["value"] += progress_step
            progress_label.config(text=f"Progress: {int(progress_bar['value'])}%")
        else:
            results_listbox.insert(tk.END, "Scan complete!")

        scan_button.config(state=tk.NORMAL, text="Scan")
        cancel_button.config(state=tk.DISABLED)

    threading.Thread(target=run_scan, daemon=True).start()

def cancel():
    global cancel_scan
    cancel_scan = True
    cancel_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("PyNetScanner")
    root.geometry("400x300")
    root.resizable(False, False)

    network_var = tk.StringVar()

    # Input field for CIDR notation
    tk.Label(root, text="Network in CIDR Notation(e.g., 192.168.1.0/24):").pack(pady=5)
    entry_width = 23  # Length of the longest possible CIDR notation
    tk.Entry(root, textvariable=network_var, width=entry_width, justify=tk.CENTER).pack(pady=5)

    # Scan button
    scan_button = tk.Button(root, text="Scan", command=scan, width=entry_width)
    scan_button.pack(pady=5)

    # Cancel button
    cancel_button = tk.Button(root, text="Cancel", command=cancel, state=tk.DISABLED, width=entry_width)
    cancel_button.pack(pady=5)

    # Progress bar
    progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)

    progress_label = tk.Label(root, text="Progress: 0%")
    progress_label.pack()

    # Results display
    results_listbox = tk.Listbox(root, width=45, height=10)
    results_listbox.pack(pady=10)

    root.mainloop()
