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
    total_entries = 0
    failed_logins = 0
    successful_logins = 0

    try:
        with open(file_path, "r") as file:
            lines = file.readlines()

        total_entries = len(lines)

        for line in lines:
            line = line.strip()

            if "LOGIN FAILED" in line:
                failed_logins += 1

                ip = line.split()[0]

                if ip in suspicious_ips:
                    suspicious_ips[ip] += 1
                else:
                    suspicious_ips[ip] = 1

            elif "LOGIN SUCCESS" in line:
                successful_logins += 1

        for ip, count in suspicious_ips.items():
            if count >= 3:
                alerts.append(
                    f"HIGH RISK: {ip} ({count} failed attempts)"
                )
            elif count == 2:
                alerts.append(
                    f"MEDIUM RISK: {ip} ({count} failed attempts)"
                )

        result_text.delete("1.0", tk.END)

        report = f"""
LOG ANALYSIS REPORT
===================

Total Log Entries : {total_entries}
Successful Logins : {successful_logins}
Failed Logins     : {failed_logins}

"""

        if alerts:
            report += "SUSPICIOUS ACTIVITY DETECTED\n"
            report += "----------------------------\n\n"

            for alert in alerts:
                report += alert + "\n"

            status_label.config(
                text="⚠ Suspicious Activity Detected",
                fg="red"
            )

        else:
            report += "No suspicious activity detected.\n"

            status_label.config(
                text="✓ System Appears Safe",
                fg="green"
            )

        result_text.insert(tk.END, report)

        save_report(report)

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def save_report(report):
    with open("intrusion_report.txt", "w") as file:
        file.write(report)

def clear_results():
    result_text.delete("1.0", tk.END)

    status_label.config(
        text="Waiting For Analysis...",
        fg="blue"
    )

root = tk.Tk()
root.title("Log Analysis & Intrusion Detection")
root.geometry("800x600")
root.resizable(False, False)

title = tk.Label(
    root,
    text="Log Analysis & Intrusion Detection System",
    font=("Arial", 20, "bold")
)
title.pack(pady=15)

status_label = tk.Label(
    root,
    text="Waiting For Analysis...",
    font=("Arial", 12, "bold"),
    fg="blue"
)
status_label.pack()

analyze_button = tk.Button(
    root,
    text="Select Log File & Analyze",
    command=analyze_log,
    width=30
)
analyze_button.pack(pady=10)

clear_button = tk.Button(
    root,
    text="Clear Results",
    command=clear_results,
    width=30
)
clear_button.pack(pady=5)

result_text = tk.Text(
    root,
    height=22,
    width=90
)
result_text.pack(pady=15)

root.mainloop()
