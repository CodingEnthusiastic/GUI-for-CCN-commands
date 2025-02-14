import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import webbrowser

# Commands and their descriptions
COMMANDS_INFO = {
    "ping <hostname>": "Check the connectivity to a host.",
    "nslookup <hostname>": "Get the IP address of a host.",
    "tracert <hostname>": "Trace the route packets take to the host.",
    "ipconfig": "Display IP configuration details.",
    "netstat": "Show network connections and statistics.",
    "arp -a": "Display ARP table entries.",
    "whoami": "Show the current logged-in user.",
    "tasklist": "List all running processes.",
    "shutdown /r /t 0": "Restart the computer immediately. [Use with care!]",
    "del <filename>": "Delete a file. [Use with care!]",
    "mkdir <directory>": "Create a new directory.",
    "rmdir <directory>": "Remove an empty directory. [Use with care!]",
    "systeminfo": "Display detailed system information.",
}

# Function to execute commands and display output
def execute_command(command):
    try:
        # Execute the command and capture the output
        result = subprocess.run(command, shell=True, text=True, capture_output=True, encoding='utf-8')

        # Display the output or error
        if result.stdout:
            output_text.insert(tk.END, f"$ {command}\n{result.stdout}\n")
        if result.stderr:
            output_text.insert(tk.END, f"$ {command}\nError: {result.stderr}\n", "error")

        output_text.see(tk.END)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to execute command: {str(e)}")

# Update the syntax in the input field when a button is clicked
def update_syntax(command):
    command_input.delete(0, tk.END)
    command_input.insert(0, command)

# Show tooltip with description
def on_hover(event, desc):
    x, y = event.widget.winfo_pointerxy()
    tooltip.geometry(f"+{x + 10}+{y + 10}")
    tooltip_label.config(text=desc)
    tooltip.deiconify()

# Hide tooltip
def off_hover(event):
    tooltip.withdraw()

# Handle Enter key for command execution
def handle_enter(event):
    command = command_input.get().strip()
    if command:
        execute_command(command)

# Show the help window
def show_help():
    help_window = tk.Toplevel(root)
    help_window.title("Help - Available Commands")
    help_window.geometry("600x400")
    help_window.configure(bg="#f0f8ff")

    search_label = tk.Label(help_window, text="Search Command:", font=("Arial", 12), bg="#f0f8ff")
    search_label.pack(pady=5)

    search_entry = ttk.Entry(help_window, width=50)
    search_entry.pack(pady=5)

    result_text = tk.Text(help_window, wrap=tk.WORD, font=("Courier", 10), bg="#ffffff", fg="#000000", state=tk.NORMAL, height=15)
    result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Search functionality in the help window
    def search_commands():
        query = search_entry.get().strip().lower()
        result_text.delete(1.0, tk.END)
        for cmd, desc in COMMANDS_INFO.items():
            if query in cmd.lower() or query in desc.lower():
                warning = "[Use with care!]" if "[Use with care!]" in desc else ""
                result_text.insert(tk.END, f"{cmd} - {desc}\n", "warning" if warning else "normal")

    search_button = ttk.Button(help_window, text="Search", command=search_commands)
    search_button.pack(pady=5)

    result_text.tag_config("warning", foreground="red")
    result_text.tag_config("normal", foreground="black")

# Open resource links in the browser
def open_resources():
    resource_window = tk.Toplevel(root)
    resource_window.title("Resources")
    resource_window.geometry("500x300")
    resource_window.configure(bg="#f0f8ff")

    links = [
        ("Learn Networking Commands", "https://www.networkcomputing.com/networking"),
        ("Windows Command Prompt Basics", "https://www.windows-commandline.com"),
        ("Networking Tutorials (YouTube)", "https://www.youtube.com/results?search_query=networking+commands"),
    ]

    tk.Label(resource_window, text="Documentation and Resources", font=("Arial", 14, "bold"), bg="#f0f8ff").pack(pady=10)
    for title, url in links:
        link = tk.Label(resource_window, text=title, font=("Arial", 12), fg="blue", cursor="hand2", bg="#f0f8ff")
        link.pack(pady=5)
        link.bind("<Button-1>", lambda e, link=url: webbrowser.open(link))

# Initialize the main window
root = tk.Tk()
root.title("Enhanced Network Commands Tool")
root.geometry("1100x700")
root.resizable(False, False)
root.configure(bg="#f0f8ff")

# Title Label
title_label = tk.Label(root, text="GUI for Enhanced Network Commands Tool", font=("Arial", 20, "bold"), bg="#f0f8ff", fg="#2e4a62")
title_label.pack(pady=10)

# Instruction Label
instruction_label = tk.Label(root, text="Click a command button or modify the syntax below and press Enter to execute.", font=("Arial", 12), bg="#f0f8ff", fg="#2e4a62")
instruction_label.pack(pady=5)

# Command Input Box
command_input = ttk.Entry(root, font=("Courier", 12))
command_input.pack(pady=5, fill=tk.X, padx=10)
command_input.bind("<Return>", handle_enter)

# Frame for output
output_frame = ttk.LabelFrame(root, text="Command Output")
output_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Text widget for output
output_text = tk.Text(output_frame, wrap=tk.WORD, font=("Courier", 10), bg="#ffffff", fg="#000000", state=tk.NORMAL)
output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Add vertical scrollbar to the output text widget
scrollbar = ttk.Scrollbar(output_frame, command=output_text.yview)
output_text.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Frame for command buttons
button_frame = ttk.LabelFrame(root, text="Commands")
button_frame.place(x=850, y=50, width=230, height=600)

# Tooltip for hover effect
tooltip = tk.Toplevel(root)
tooltip.withdraw()
tooltip.overrideredirect(True)
tooltip_label = tk.Label(tooltip, text="", font=("Arial", 10), bg="yellow", wraplength=200)
tooltip_label.pack()

# Create command buttons with hover effects
colors = ["#f0a", "#0af", "#0fa", "#fa0", "#a0f", "#af0"]
for i, (cmd, desc) in enumerate(COMMANDS_INFO.items()):
    def make_command(c):
        return lambda: update_syntax(c)

    btn = ttk.Button(button_frame, text=cmd.split()[0], command=make_command(cmd))
    btn.configure(style=f"Command.TButton")
    btn.pack(pady=5, fill=tk.X)

    # Bind hover events
    btn.bind("<Enter>", lambda e, d=desc: on_hover(e, d))
    btn.bind("<Leave>", off_hover)

# Footer Label
footer_label = tk.Label(root, text="Developed with simplicity and clarity for all users", font=("Arial", 10), bg="#f0f8ff", fg="#2e4a62")
footer_label.pack(pady=10)

# Help and Resource Buttons
help_button = ttk.Button(root, text="Help", command=show_help)
help_button.place(x=850, y=670)

resource_button = ttk.Button(root, text="Resources", command=open_resources)
resource_button.place(x=950, y=670)

# Run the GUI application
root.mainloop()
