import tkinter as tk
import platform
import psutil
import uuid
import socket
import subprocess

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

def show_info():
    info = get_system_info()
    result_text.delete(1.0, tk.END)
    for key, value in info.items():
        result_text.insert(tk.END, f"{key}: {value}\n")

# GUI setup
app = tk.Tk()
app.title("System Information")
app.geometry("400x300")

tk.Label(app, text="System Info App", font=("Arial", 16)).pack(pady=10)
tk.Button(app, text="Get System Info", command=show_info).pack(pady=5)

result_text = tk.Text(app, height=10, width=50)
result_text.pack()

app.mainloop()