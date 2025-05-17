import socket
import ssl
import threading
import random
import string
import time
import tkinter as tk
from tkinter import simpledialog, messagebox, font, ttk

SERVER_ADDR = '127.0.0.1'
SERVER_PORT = 9999
LOG_FILE = "client_login.log"


class ChatClient:
    def __init__(self):
        self.sock = None
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        self.root = tk.Tk()
        self.root.title("Secure Chat Client")
        self.root.geometry("600x450")
        self.root.configure(bg="#2c3e50")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.font_normal = font.Font(family="Segoe UI", size=10)
        self.font_bold = font.Font(family="Segoe UI", size=10, weight="bold")
        self.title_font = font.Font(family="Segoe UI", size=14, weight="bold")

        self.container = tk.Frame(self.root, bg="#2c3e50")
        self.container.pack(fill=tk.BOTH, expand=True)

        self.login_and_connect()

        self.root.mainloop()

    def log_login_attempt(self, username, password, success):
        with open(LOG_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Username: {username}, Password: {password}, Success: {success}\n")

    def generate_captcha(self, length=5):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def generate_room_key(self, length=8):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def login_and_connect(self):
        while True:
            self.action = simpledialog.askstring("Login or Register", "Type 'login' or 'register':", parent=self.root)
            if self.action is None:
                self.root.destroy()
                return
            self.action = self.action.lower()
            if self.action not in ['login', 'register']:
                messagebox.showerror("Error", "Please type 'login' or 'register'.")
                continue
            break

        self.username = simpledialog.askstring("Username", "Enter username:", parent=self.root)
        if self.username is None:
            self.root.destroy()
            return
        self.password = simpledialog.askstring("Password", "Enter password:", parent=self.root, show='*')
        if self.password is None:
            self.root.destroy()
            return

        while True:
            captcha = self.generate_captcha()
            user_captcha = simpledialog.askstring("Captcha", f"Enter this code:\n{captcha}", parent=self.root)
            if user_captcha is None:
                self.root.destroy()
                return
            if user_captcha != captcha:
                messagebox.showerror("Captcha Error", "Incorrect captcha. Try again.")
                continue
            break

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = self.context.wrap_socket(raw_sock, server_hostname=SERVER_ADDR)
        try:
            self.sock.connect((SERVER_ADDR, SERVER_PORT))
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))
            self.root.destroy()
            return

        login_str = f"{self.action}|{self.username}|{self.password}||"
        self.sock.send(login_str.encode())

        response = self.sock.recv(1024).decode()

        success = (response == 'OK')
        self.log_login_attempt(self.username, self.password, success)

        self.sock.close()
        self.sock = None

        if not success:
            messagebox.showerror("Server Error", f"Server response: {response}")
            self.root.destroy()
            return

        self.show_main_screen()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_main_screen(self):
        self.clear_container()

        title_lbl = tk.Label(self.container, text=f"Welcome, {self.username}", font=self.title_font, fg="white", bg="#2c3e50")
        title_lbl.pack(pady=15)

        tabs = ttk.Notebook(self.container)
        tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        profile_tab = ttk.Frame(tabs)
        tabs.add(profile_tab, text="Profile")

        tk.Label(profile_tab, text=f"Username: {self.username}", font=self.font_bold).pack(pady=10, anchor="w", padx=10)

        friends_tab = ttk.Frame(tabs)
        tabs.add(friends_tab, text="Friends")
        tk.Label(friends_tab, text="Friends List", font=self.font_bold).pack(pady=20)

        rooms_tab = ttk.Frame(tabs)
        tabs.add(rooms_tab, text="Chat Rooms")

        tk.Label(rooms_tab, text="Select a Chat Room:", font=self.font_bold).pack(pady=10)

        rooms = ["Europe", "USA", "Asia", "private"]
        for r in rooms:
            btn = tk.Button(rooms_tab, text=r.capitalize(), font=self.font_normal,
                            width=15, command=lambda room=r: self.open_room(room))
            btn.pack(pady=5)

        host_btn = tk.Button(rooms_tab, text="Host Private Room", font=self.font_bold,
                             width=20, bg="#2980b9", fg="white", command=self.host_private_room)
        host_btn.pack(pady=15)

    def host_private_room(self):
        room_key = self.generate_room_key()

        messagebox.showinfo("Private Room Key", f"Your generated room key is:\n\n{room_key}\n\n"
                                                "Copy this key and give it to people you want to allow in your private room.")

        room_name = simpledialog.askstring("Room Name", "Enter private room name (or leave blank for 'private'):", parent=self.root)
        if room_name is None:
            return
        if room_name.strip() == '':
            room_name = 'private'

        set_pass = messagebox.askyesno("Password?", "Do you want to set a password for your private room? (optional)")

        room_pass = ""
        if set_pass:
            room_pass = simpledialog.askstring("Room Password", "Enter password for your private room:", parent=self.root, show='*')
            if room_pass is None:
                return

        self.room = room_name
        self.key = room_key
        self.password_for_room = room_pass

        self.connect_to_room(host=True)

    def open_room(self, room):
        self.room = room
        self.key = ''
        self.password_for_room = ''

        if room == 'private':

            key = simpledialog.askstring("Private Room Key", "Enter private room key:", parent=self.root)
            if key is None:
                return
            self.key = key


            pass_try = simpledialog.askstring("Private Room Password",
                                              "Enter password for this private room (leave empty if none):",
                                              parent=self.root, show='*')
            if pass_try is None:
                return
            self.password_for_room = pass_try

        self.connect_to_room(host=False)

    def connect_to_room(self, host=False):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = self.context.wrap_socket(raw_sock, server_hostname=SERVER_ADDR)
        try:
            self.sock.connect((SERVER_ADDR, SERVER_PORT))
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))
            self.show_main_screen()
            return

        login_str = f"login|{self.username}|{self.password}|{self.room}|{self.key}|{self.password_for_room}"
        self.sock.send(login_str.encode())

        response = self.sock.recv(1024).decode()
        if response != "OK":
            messagebox.showerror("Server Error", f"Server response: {response}")
            self.sock.close()
            self.sock = None
            self.show_main_screen()
            return

        self.show_chat_screen()
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_chat_screen(self):
        self.clear_container()

        topbar = tk.Frame(self.container, bg="#34495e")
        topbar.pack(fill=tk.X)

        back_btn = tk.Button(topbar, text="← Back", font=self.font_bold,
                             bg="#e74c3c", fg="white", command=self.leave_room)
        back_btn.pack(side=tk.LEFT, padx=5, pady=5)

        room_lbl = tk.Label(topbar, text=f"Room: {self.room.capitalize()}", font=self.font_bold, fg="white", bg="#34495e")
        room_lbl.pack(side=tk.LEFT, padx=20, pady=5)

        self.text_area = tk.Text(self.container, state='disabled', bg="#34495e", fg="white",
                                 font=self.font_normal, padx=10, pady=10, wrap=tk.WORD, height=18)
        self.text_area.pack(padx=10, pady=(10, 5), fill=tk.BOTH, expand=True)

        bottom_frame = tk.Frame(self.container, bg="#2c3e50")
        bottom_frame.pack(padx=10, pady=5, fill=tk.X)

        self.entry_msg = tk.Entry(bottom_frame, font=self.font_normal, bg="#ecf0f1")
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5)
        self.entry_msg.bind("<Return>", lambda event: self.send_message())

        self.send_btn = tk.Button(bottom_frame, text="Send", font=self.font_bold,
                                  bg="#27ae60", fg="white", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT, padx=(10, 0), pady=5)

        self.append_message(f"*** Joined {self.room.capitalize()} room ***")

    def leave_room(self):
        try:
            if self.sock:
                self.sock.close()
                self.sock = None
        except:
            pass
        self.show_main_screen()

    def append_message(self, msg):
        if not hasattr(self, 'text_area') or self.text_area is None:
            return
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg + '\n')
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def send_message(self):
        msg = self.entry_msg.get().strip()
        if not msg or not self.sock:
            return
        full_msg = f"{self.username}: {msg}"
        try:
            self.sock.send(full_msg.encode())
            self.append_message(f"You: {msg}")
            self.entry_msg.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Send failed: {e}")
            self.leave_room()

    def receive_messages(self):
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                msg = data.decode()
                self.append_message(msg)
        except Exception:
            pass
        finally:
            messagebox.showinfo("Disconnected", "Server closed the connection.")
            self.leave_room()

    def on_close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.root.destroy()


if __name__ == "__main__":
    ChatClient()