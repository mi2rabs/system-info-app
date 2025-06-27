import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import platform
import psutil
import uuid
import socket
import subprocess
import wmi


def get_local_info():
    try:
        system_name = platform.node()
        ram_size = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                for ele in range(0, 8 * 6, 8)][::-1])
        os_info = platform.system() + " " + platform.release()
        ip_address = socket.gethostbyname(socket.gethostname())
        try:
            serial = subprocess.check_output("wmic bios get serialnumber").decode().split("\n")[1].strip()
        except:
            serial = "Unavailable"

        return {
            "System Name": system_name,
            "RAM Size (GB)": ram_size,
            "MAC Address": mac_address,
            "Operating System": os_info,
            "IP Address": ip_address,
            "Serial Number": serial
        }
    except Exception as e:
        return {"Error": str(e)}


def display_local_info():
    info = get_local_info()
    local_result_box.delete(1.0, tk.END)
    for key, value in info.items():
        local_result_box.insert(tk.END, f"{key}: {value}\n")


def scan_branch():
    start_ip = start_ip_entry.get()
    end_ip = end_ip_entry.get()

    if not start_ip or not end_ip:
        messagebox.showwarning("Input Error", "Please enter both start and end IP addresses.")
        return

    try:
        # Extract last octet range
        base_ip = ".".join(start_ip.split('.')[:3]) + '.'
        start = int(start_ip.split('.')[-1])
        end = int(end_ip.split('.')[-1])

        username = simpledialog.askstring("Username", "Enter admin username (e.g. DOMAIN\\Admin):")
        password = simpledialog.askstring("Password", "Enter password:", show="*")

        network_result_box.delete(1.0, tk.END)

        for i in range(start, end + 1):
            ip = base_ip + str(i)
            try:
                c = wmi.WMI(computer=ip, user=username, password=password)
                for sys in c.Win32_OperatingSystem():
                    system_name = sys.CSName
                    os_info = sys.Caption
                    ram_size = round(float(sys.TotalVisibleMemorySize) / (1024 ** 2), 2)
                for bios in c.Win32_BIOS():
                    serial = bios.SerialNumber

                network_result_box.insert(tk.END, f"--- {ip} ---\n")
                network_result_box.insert(tk.END, f"System Name: {system_name}\n")
                network_result_box.insert(tk.END, f"OS: {os_info}\n")
                network_result_box.insert(tk.END, f"RAM (GB): {ram_size}\n")
                network_result_box.insert(tk.END, f"Serial: {serial}\n\n")

            except Exception as e:
                network_result_box.insert(tk.END, f"--- {ip} ---\n")
                network_result_box.insert(tk.END, f"Error: {str(e)}\n\n")

    except Exception as e:
        messagebox.showerror("Error", str(e))


# GUI Setup
app = tk.Tk()
app.title("System Info App")
app.geometry("600x500")

tab_control = ttk.Notebook(app)

# Local Info Tab
local_tab = ttk.Frame(tab_control)
tab_control.add(local_tab, text='Local Info')

tk.Label(local_tab, text="System Info", font=("Arial", 16)).pack(pady=10)
tk.Button(local_tab, text="Get System Info", command=display_local_info).pack(pady=5)

local_result_box = tk.Text(local_tab, height=20, width=70)
local_result_box.pack(pady=5)

# Scan Branch Tab
network_tab = ttk.Frame(tab_control)
tab_control.add(network_tab, text='Scan Branch')

tk.Label(network_tab, text="Scan IP Range", font=("Arial", 16)).pack(pady=10)

entry_frame = tk.Frame(network_tab)
entry_frame.pack(pady=5)

tk.Label(entry_frame, text="Start IP:").grid(row=0, column=0, padx=5, pady=5)
start_ip_entry = tk.Entry(entry_frame)
start_ip_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(entry_frame, text="End IP:").grid(row=0, column=2, padx=5, pady=5)
end_ip_entry = tk.Entry(entry_frame)
end_ip_entry.grid(row=0, column=3, padx=5, pady=5)

tk.Button(network_tab, text="Scan", command=scan_branch).pack(pady=10)

network_result_box = tk.Text(network_tab, height=20, width=70)
network_result_box.pack(pady=5)

tab_control.pack(expand=1, fill='both')
app.mainloop()
