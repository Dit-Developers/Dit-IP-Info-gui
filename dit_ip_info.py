import tkinter as tk
from tkinter import messagebox, ttk
import requests
import subprocess
import socket
import nmap
import webbrowser
import os

def open_function_window(function):
    function_window = tk.Toplevel(root)
    function_window.title(function)
    function_window.geometry("600x400")
    function_window.configure(bg="#333333")

    if function == "IP Info":
        create_ip_info_window(function_window)
    elif function == "Ping IP":
        create_ping_ip_window(function_window)
    elif function == "Get Website IP":
        create_get_website_ip_window(function_window)
    elif function == "Get Local IP":
        create_get_local_ip_window(function_window)
    elif function == "Nmap Scan":
        create_nmap_scan_window(function_window)
    elif function == "DNS Lookup":
        create_dns_lookup_window(function_window)
    elif function == "Port Check":
        create_port_check_window(function_window)
    elif function == "Traceroute":
        create_traceroute_window(function_window)
    elif function == "Geolocation":
        create_geolocation_window(function_window)
    elif function == "Scan for Open Ports":
        create_scan_open_ports_window(function_window)
    elif function == "Restrict Access":
        create_restrict_access_window(function_window)
    elif function == "Discover Personal Info":
        create_discover_personal_info_window(function_window)
    elif function == "Vulnerability Finder":
        create_vulnerability_finder_window(function_window)
    elif function == "Exploit IP":
        create_exploit_ip_window(function_window)
    elif function == "Check Web Server Paths":
        create_check_web_paths_window(function_window)
    elif function == "Developer":
        open_developer_website()

def create_ip_info_window(window):
    def info():
        ip = ip_entry.get()
        try:
            response = requests.get(url=f"http://ip-api.com/json/{ip}").json()
            info_text.delete("1.0", tk.END)
            info_text.insert(tk.END, f"IP: {response.get('query')}\nCountry: {response.get('country')}\nRegion: {response.get('regionName')}\nCity: {response.get('city')}\nZip-code: {response.get('zip')}\nLat: {response.get('lat')}\nLong: {response.get('lon')}\nTimezone: {response.get('timezone')}\nProvider: {response.get('isp')}\nOrganization: {response.get('org')}\nStatus: {response.get('status')}\n", "info")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    info_button = tk.Button(window, text="Get Info", command=info, bg="#007bff", fg="white", font=("Courier", 12))
    info_button.pack()

    info_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    info_text.pack()

def create_ping_ip_window(window):
    def ping():
        ip = ip_entry.get()
        try:
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '4', ip]
            response = subprocess.run(command, capture_output=True, text=True)
            ping_text.delete("1.0", tk.END)
            ping_text.insert(tk.END, response.stdout)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    ping_button = tk.Button(window, text="Ping IP", command=ping, bg="#007bff", fg="white", font=("Courier", 12))
    ping_button.pack()

    ping_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    ping_text.pack()

def create_get_website_ip_window(window):
    def get_website_ip():
        website = website_entry.get()
        try:
            ip = socket.gethostbyname(website)
            website_ip_text.delete("1.0", tk.END)
            website_ip_text.insert(tk.END, f"The IP address of {website} is {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    website_label = tk.Label(window, text="Enter Website URL:", bg="#333333", fg="white", font=("Courier", 12))
    website_label.pack()
    website_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    website_entry.pack()

    website_ip_button = tk.Button(window, text="Get Website IP", command=get_website_ip, bg="#007bff", fg="white", font=("Courier", 12))
    website_ip_button.pack()

    website_ip_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    website_ip_text.pack()

def create_get_local_ip_window(window):
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            local_ip_text.delete("1.0", tk.END)
            local_ip_text.insert(tk.END, f"Your Local IP address is {local_ip}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    get_local_ip_button = tk.Button(window, text="Get Local IP", command=get_local_ip, bg="#007bff", fg="white", font=("Courier", 12))
    get_local_ip_button.pack()

    local_ip_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    local_ip_text.pack()

def create_nmap_scan_window(window):
    def nmap_scan():
        ip = ip_entry.get()
        try:
            nm = nmap.PortScanner()
            nm.scan(ip)
            nmap_results_text.delete("1.0", tk.END)
            nmap_results_text.insert(tk.END, str(nm.all_hosts()))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP for Nmap scan:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    nmap_button = tk.Button(window, text="Nmap Scan", command=nmap_scan, bg="#007bff", fg="white", font=("Courier", 12))
    nmap_button.pack()

    nmap_results_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    nmap_results_text.pack()

def create_dns_lookup_window(window):
    def dns_lookup():
        ip = ip_entry.get()
        try:
            hostname = socket.gethostbyaddr(ip)
            dns_lookup_text.delete("1.0", tk.END)
            dns_lookup_text.insert(tk.END, f"The hostname for {ip} is {hostname[0]}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP for DNS lookup:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    dns_lookup_button = tk.Button(window, text="DNS Lookup", command=dns_lookup, bg="#007bff", fg="white", font=("Courier", 12))
    dns_lookup_button.pack()

    dns_lookup_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    dns_lookup_text.pack()

def create_port_check_window(window):
    def port_check():
        ip = ip_entry.get()
        port = port_entry.get()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, int(port)))
            s.close()
            port_check_text.delete("1.0", tk.END)
            if result == 0:
                port_check_text.insert(tk.END, f"Port {port} on {ip} is open")
            else:
                port_check_text.insert(tk.END, f"Port {port} on {ip} is closed")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    port_label = tk.Label(window, text="Enter Port number:", bg="#333333", fg="white", font=("Courier", 12))
    port_label.pack()
    port_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    port_entry.pack()

    port_check_button = tk.Button(window, text="Check Port", command=port_check, bg="#007bff", fg="white", font=("Courier", 12))
    port_check_button.pack()

    port_check_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    port_check_text.pack()

def create_traceroute_window(window):
    def traceroute():
        ip = ip_entry.get()
        try:
            param = 'tracert' if os.name == 'nt' else 'traceroute'
            command = [param, ip]
            response = subprocess.run(command, capture_output=True, text=True)
            traceroute_text.delete("1.0", tk.END)
            traceroute_text.insert(tk.END, response.stdout)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP for Traceroute:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    traceroute_button = tk.Button(window, text="Traceroute", command=traceroute, bg="#007bff", fg="white", font=("Courier", 12))
    traceroute_button.pack()

    traceroute_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    traceroute_text.pack()

def create_geolocation_window(window):
    def geolocation():
        ip = ip_entry.get()
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/geo").json()
            geolocation_text.delete("1.0", tk.END)
            geolocation_text.insert(tk.END, f"IP: {response.get('ip')}\nCity: {response.get('city')}\nRegion: {response.get('region')}\nCountry: {response.get('country')}\nLocation: {response.get('loc')}\nOrg: {response.get('org')}\nPostal: {response.get('postal')}\nTimezone: {response.get('timezone')}\n")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP for Geolocation:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    geolocation_button = tk.Button(window, text="Geolocation", command=geolocation, bg="#007bff", fg="white", font=("Courier", 12))
    geolocation_button.pack()

    geolocation_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    geolocation_text.pack()

def create_scan_open_ports_window(window):
    def scan_open_ports():
        ip = ip_entry.get()
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, '1-65535')
            scan_results_text.delete("1.0", tk.END)
            for proto in nm[ip].all_protocols():
                lport = nm[ip][proto].keys()
                for port in lport:
                    scan_results_text.insert(tk.END, f"Port: {port}\tState: {nm[ip][proto][port]['state']}\n")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP to scan for open ports:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    scan_button = tk.Button(window, text="Scan Ports", command=scan_open_ports, bg="#007bff", fg="white", font=("Courier", 12))
    scan_button.pack()

    scan_results_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    scan_results_text.pack()

def create_restrict_access_window(window):
    def restrict_access():
        ip = ip_entry.get()
        # Implementing restriction requires root/admin privileges and is OS-specific
        # Here we'll just show a message box
        messagebox.showinfo("Info", f"Restricting access to {ip} (requires admin privileges)")

    ip_label = tk.Label(window, text="Enter IP to restrict access:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    restrict_button = tk.Button(window, text="Restrict Access", command=restrict_access, bg="#007bff", fg="white", font=("Courier", 12))
    restrict_button.pack()

def create_discover_personal_info_window(window):
    def discover_personal_info():
        ip = ip_entry.get()
        try:
            response = requests.get(f"https://ipinfo.io/{ip}").json()
            personal_info_text.delete("1.0", tk.END)
            personal_info_text.insert(tk.END, f"IP: {response.get('ip')}\nHostname: {response.get('hostname')}\nCity: {response.get('city')}\nRegion: {response.get('region')}\nCountry: {response.get('country')}\nLocation: {response.get('loc')}\nOrganization: {response.get('org')}\nPostal: {response.get('postal')}\nTimezone: {response.get('timezone')}\n")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP to discover personal info:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    discover_button = tk.Button(window, text="Discover Info", command=discover_personal_info, bg="#007bff", fg="white", font=("Courier", 12))
    discover_button.pack()

    personal_info_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    personal_info_text.pack()

def create_vulnerability_finder_window(window):
    def vulnerability_finder():
        ip = ip_entry.get()
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='--script vuln')
            vuln_results_text.delete("1.0", tk.END)
            vuln_results_text.insert(tk.END, str(nm[ip]))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP to find vulnerabilities:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    vuln_button = tk.Button(window, text="Find Vulnerabilities", command=vulnerability_finder, bg="#007bff", fg="white", font=("Courier", 12))
    vuln_button.pack()

    vuln_results_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    vuln_results_text.pack()

def create_exploit_ip_window(window):
    def exploit_ip():
        ip = ip_entry.get()
        # Implementing exploitation requires ethical considerations and specialized tools
        # Here we'll just show a message box
        messagebox.showinfo("Info", f"Exploiting IP {ip} (requires specialized tools)")

    ip_label = tk.Label(window, text="Enter IP to exploit:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    exploit_button = tk.Button(window, text="Exploit IP", command=exploit_ip, bg="#007bff", fg="white", font=("Courier", 12))
    exploit_button.pack()

def create_check_web_paths_window(window):
    def check_web_paths():
        ip = ip_entry.get()
        common_paths = ['/admin', '/login', '/dashboard']
        try:
            check_paths_text.delete("1.0", tk.END)
            for path in common_paths:
                response = requests.get(f"http://{ip}{path}")
                if response.status_code == 200:
                    check_paths_text.insert(tk.END, f"Path found: {path}\n")
                else:
                    check_paths_text.insert(tk.END, f"Path not found: {path}\n")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    ip_label = tk.Label(window, text="Enter IP to check web server paths:", bg="#333333", fg="white", font=("Courier", 12))
    ip_label.pack()
    ip_entry = tk.Entry(window, bg="#555555", fg="white", font=("Courier", 12))
    ip_entry.pack()

    check_paths_button = tk.Button(window, text="Check Paths", command=check_web_paths, bg="#007bff", fg="white", font=("Courier", 12))
    check_paths_button.pack()

    check_paths_text = tk.Text(window, height=10, width=60, bg="#555555", fg="white", font=("Courier", 12))
    check_paths_text.pack()

def open_developer_website():
    webbrowser.open("https://msue.vercel.app")

root = tk.Tk()
root.title("DIT IP Info Tool")
root.geometry("800x600")
root.configure(bg="#333333")

title_label = tk.Label(root, text="DIT IP Info Tool", bg="#333333", fg="white", font=("Courier", 24))
title_label.pack(pady=10)

functions = ["IP Info", "Ping IP", "Get Website IP", "Get Local IP", "Nmap Scan", "DNS Lookup", "Port Check", "Traceroute", "Geolocation", "Scan for Open Ports", "Restrict Access", "Discover Personal Info", "Vulnerability Finder", "Exploit IP", "Check Web Server Paths", "Developer"]

buttons_frame = tk.Frame(root, bg="#333333")
buttons_frame.pack(pady=20)

for function in functions:
    function_button = tk.Button(buttons_frame, text=function, command=lambda f=function: open_function_window(f), bg="#007bff", fg="white", font=("Courier", 12), width=20)
    function_button.pack(pady=5)

root.mainloop()
