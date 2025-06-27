import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import platform
import psutil
import uuid
import socket
import subprocess
import textwrap

# ---------- Local System Info ----------
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


# ---------- Remote Scan ----------
def scan_branch():
    start_ip = start_ip_entry.get()
    end_ip = end_ip_entry.get()

    if not start_ip or not end_ip:
        messagebox.showwarning("Input Error", "Please enter both start and end IP addresses.")
        return

    try:
        base_ip = ".".join(start_ip.split('.')[:3]) + '.'
        start = int(start_ip.split('.')[-1])
        end = int(end_ip.split('.')[-1])

        username = simpledialog.askstring("Username", "Enter admin username (DOMAIN\\Username):")
        password = simpledialog.askstring("Password", "Enter password:", show="*")

        if not username or not password or "\\" not in username:
            messagebox.showwarning("Credentials", "Please enter valid DOMAIN\\Username format.")
            return

        network_result_box.delete(1.0, tk.END)

        for i in range(start, end + 1):
            ip = base_ip + str(i)

            ps_script = textwrap.dedent(f"""
                $secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential('{username}', $secure)
                Invoke-Command -ComputerName {ip} -Credential $cred -ScriptBlock {{
                    try {{
                        $cs = Get-WmiObject Win32_ComputerSystem
                        $os = Get-WmiObject Win32_OperatingSystem
                        $bios = Get-WmiObject Win32_BIOS

                        $info = [PSCustomObject]@{{
                            "System Name" = $cs.Name
                            "OS" = $os.Caption
                            "RAM (GB)" = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                            "Serial Number" = $bios.SerialNumber
                        }}
                        $info | ConvertTo-Json -Compress
                    }} catch {{
                        "Error: $($_.Exception.Message)"
                    }}
                }}
            """)

            try:
                result = subprocess.check_output(["powershell", "-Command", ps_script],
                                                 stderr=subprocess.STDOUT,
                                                 text=True,
                                                 timeout=15)
                network_result_box.insert(tk.END, f"--- {ip} ---\n{result.strip()}\n\n")
            except subprocess.CalledProcessError as e:
                network_result_box.insert(tk.END, f"--- {ip} ---\nError: {e.output.strip()}\n\n")
            except subprocess.TimeoutExpired:
                network_result_box.insert(tk.END, f"--- {ip} ---\nError: Request timed out.\n\n")

    except Exception as e:
        messagebox.showerror("Error", str(e))


# ---------- GUI Setup ----------
app = tk.Tk()
app.title("System Info App")
app.geometry("600x500")

tab_control = ttk.Notebook(app)

# Local Info Tab
local_tab = ttk.Frame(tab_control)
tab_control.add(local_tab, text="Local Info")

tk.Button(local_tab, text="Get Local System Info", command=display_local_info).pack(pady=10)
local_result_box = tk.Text(local_tab, height=15, width=70)
local_result_box.pack(padx=10, pady=5)

# Network Scan Tab
network_tab = ttk.Frame(tab_control)
tab_control.add(network_tab, text="Scan Branch")

frame = tk.Frame(network_tab)
frame.pack(pady=10)

tk.Label(frame, text="Start IP:").grid(row=0, column=0)
start_ip_entry = tk.Entry(frame)
start_ip_entry.grid(row=0, column=1)

tk.Label(frame, text="End IP:").grid(row=0, column=2)
end_ip_entry = tk.Entry(frame)
end_ip_entry.grid(row=0, column=3)

tk.Button(frame, text="Scan", command=scan_branch).grid(row=0, column=4, padx=10)

network_result_box = tk.Text(network_tab, height=15, width=70)
network_result_box.pack(padx=10, pady=5)

tab_control.pack(expand=1, fill="both")
app.mainloop()

