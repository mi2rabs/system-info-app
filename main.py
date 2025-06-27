import tkinter as tk
from tkinter import ttk, messagebox
import platform
import psutil
import uuid
import socket
import subprocess
import wmi

# --- Get Local System Info ---
def get_system_info():
    try:
        system_name = platform.node()
        ram_size = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                for ele in range(0, 8*6, 8)][::-1])
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

def show_local_info():
    info = get_system_info()
    result_text.delete(1.0, tk.END)
    for key, value in info.items():
        result_text.insert(tk.END, f"{key}: {value}\n")

# --- Get Remote Info using WMI ---
def get_remote_info(ip, username, password):
    try:
        conn = wmi.WMI(computer=ip, user=username, password=password)
        for os in conn.Win32_OperatingSystem():
            return {
                "IP": ip,
                "Computer Name": os.CSName,
                "OS": os.Caption,
                "RAM (MB)": round(int(os.TotalVisibleMemorySize) / 1024)
            }
    except Exception as e:
        return {"IP": ip, "Error": str(e)}

def fetch_remote_info():
    ip = ip_entry.get()
    user = user_entry.get()
    pwd = password_entry.get()

    if not ip or not user or not pwd:
        messagebox.showerror("Input Error", "All fields are required.")
        return

    info = get_remote_info(ip, user, pwd)

    for item in tree.get_children():
        tree.delete(item)

    if "Error" in info:
        messagebox.showerror("Connection Failed", f"{ip}: {info['Error']}")
    else:
        tree.insert("", "end", values=(info["IP"], info["Computer Name"], info["OS"], info["RAM (MB)"]))

# === GUI SETUP ===
app = tk.Tk()
app.title("System Info App")
app.geometry("600x400")

tab_control = ttk.Notebook(app)

# === Local Info Tab ===
local_tab = ttk.Frame(tab_control)
tab_control.add(local_tab, text='Local Info')

ttk.Label(local_tab, text="System Info App", font=("Arial", 16)).pack(pady=10)
ttk.Button(local_tab, text="Get System Info", command=show_local_info).pack(pady=5)

result_text = tk.Text(local_tab, height=12, width=70)
result_text.pack(padx=10, pady=5)

# === Network Info Tab ===
network_tab = ttk.Frame(tab_control)
tab_control.add(network_tab, text='Network Info')

ttk.Label(network_tab, text="Target IP:").grid(row=0, column=0, sticky="e", padx=10, pady=5)
ip_entry = ttk.Entry(network_tab, width=30)
ip_entry.grid(row=0, column=1)

ttk.Label(network_tab, text="Username:").grid(row=1, column=0, sticky="e", padx=10)
user_entry = ttk.Entry(network_tab, width=30)
user_entry.grid(row=1, column=1)

ttk.Label(network_tab, text="Password:").grid(row=2, column=0, sticky="e", padx=10)
password_entry = ttk.Entry(network_tab, show="*", width=30)
password_entry.grid(row=2, column=1)

ttk.Button(network_tab, text="Get Info", command=fetch_remote_info).grid(row=3, column=0, columnspan=2, pady=10)

tree = ttk.Treeview(network_tab, columns=("IP", "Computer Name", "OS", "RAM (MB)"), show='headings', height=6)
for col in ("IP", "Computer Name", "OS", "RAM (MB)"):
    tree.heading(col, text=col)
    tree.column(col, width=130)
tree.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

tab_control.pack(expand=1, fill='both')
app.mainloop()
