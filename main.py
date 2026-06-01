import tkinter as tk
from tkinter import filedialog, messagebox

def analyze_log():
    file_path = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[("Text Files", "*.txt")]
    )

    if not file_path:
        return

    suspicious_ips = {}
    alerts = []

    try:
        with open(file_path, "r") as file:
            lines = file.readlines()

        for line in lines:
            if "LOGIN FAILED" in line:
                ip = line.split()[0]

                if ip in suspicious_ips:
                    suspicious_ips[ip] += 1
                else:
                    suspicious_ips[ip] = 1

        for ip, count in suspicious_ips.items():
            if count >= 3:
                alerts.append(
                    f"Suspicious IP: {ip} ({count} failed attempts)"
                )

        result_text.delete("1.0", tk.END)

        if alerts:
            result_text.insert(
                tk.END,
                "INTRUSION ALERTS\n\n"
            )

            for alert in alerts:
                result_text.insert(
                    tk.END,
                    alert + "\n"
                )

            save_report(alerts)

        else:
            result_text.insert(
                tk.END,
                "No suspicious activity detected."
            )

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def save_report(alerts):
    with open("intrusion_report.txt", "w") as file:
        file.write("INTRUSION DETECTION REPORT\n")
        file.write("==========================\n\n")

        for alert in alerts:
            file.write(alert + "\n")

root = tk.Tk()
root.title("Log Analysis & Intrusion Detection")
root.geometry("700x500")

title = tk.Label(
    root,
    text="Log Analysis & Intrusion Detection",
    font=("Arial", 18, "bold")
)
title.pack(pady=15)

analyze_button = tk.Button(
    root,
    text="Select Log File & Analyze",
    command=analyze_log,
    width=30
)
analyze_button.pack(pady=10)

result_text = tk.Text(
    root,
    height=18,
    width=70
)
result_text.pack(pady=10)

root.mainloop()