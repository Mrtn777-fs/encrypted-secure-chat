import tkinter as tk
from chat_client import ChatClient
import threading


class ChatApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure Chat")

        self.chat_log = tk.Text(self.window, state='disabled')
        self.chat_log.pack()

        self.msg_entry = tk.Entry(self.window)
        self.msg_entry.pack()
        self.msg_entry.bind('<Return>', self.send_message)

        self.client = ChatClient('localhost', 9999)

        threading.Thread(target=self.receive_loop, daemon=True).start()

        self.window.mainloop()

    def send_message(self, event):
        msg = self.msg_entry.get()
        self.client.send(msg)
        self.msg_entry.delete(0, tk.END)

    def receive_loop(self):
        while True:
            try:
                msg = self.client.receive()
                self.chat_log.config(state='normal')
                self.chat_log.insert(tk.END, msg + "\n")
                self.chat_log.config(state='disabled')
            except:
                break


if __name__ == '__main__':
    ChatApp()
