import socket, ssl, threading, json, os, sys
from database import verify_user, register_user
from tls_config import get_tls_context

clients = {}

rooms_path = os.path.join(os.path.dirname(__file__), "rooms.json")
with open(rooms_path, "r") as f:
    rooms = json.load(f)

PORT = 9999

def handle_client(connstream, addr):
    try:
        user_data = connstream.recv(2048).decode().split('|')
        if len(user_data) == 5:
            action, username, password, room, key = user_data
            room_password = ''
        elif len(user_data) == 6:
            action, username, password, room, key, room_password = user_data
        else:
            connstream.send(b'BAD_FORMAT')
            return

        if action == 'register':
            if not register_user(username, password):
                connstream.send(b'FAIL')
                return
            connstream.send(b'OK')
        elif action == 'login':
            if not verify_user(username, password):
                connstream.send(b'FAIL')
                return
            connstream.send(b'OK')
        else:
            connstream.send(b'BAD_ACTION')
            return

        if room not in rooms and room != 'private':
            connstream.send(b'NO_ROOM')
            return

        if room == 'private':
            if key not in rooms['private']:
                connstream.send(b'BAD_KEY')
                return

            expected_pass = rooms['private'][key].get('password', '')
            if expected_pass and expected_pass != room_password:
                connstream.send(b'BAD_PASSWORD')
                return
            room_name = rooms['private'][key]['name']
        else:
            room_name = room


        if room_name not in clients:
            clients[room_name] = []
        clients[room_name].append(connstream)

        while True:
            msg = connstream.recv(4096)
            if not msg:
                break

            for client in clients[room_name]:
                if client != connstream:
                    try:
                        client.send(msg)
                    except:
                        pass

    except Exception as e:
        print("Client error:", e)
    finally:

        for room in clients:
            if connstream in clients[room]:
                clients[room].remove(connstream)
        connstream.close()

def main():
    context = get_tls_context()
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bindsocket.bind(('0.0.0.0', PORT))
    except OSError as e:
        print(f"Failed to bind to port {PORT}: {e}")
        sys.exit(1)

    bindsocket.listen(5)
    print(f"Server listening with TLS on port {PORT}...")

    try:
        while True:
            newsocket, fromaddr = bindsocket.accept()
            connstream = context.wrap_socket(newsocket, server_side=True)
            threading.Thread(target=handle_client, args=(connstream, fromaddr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        bindsocket.close()

if __name__ == '__main__':
    main()
