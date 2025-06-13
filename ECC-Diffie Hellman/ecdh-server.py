# ecc_server.py

import socket
import time
import pickle
from tinyec import registry
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Konfigurasi Server
HOST = '127.0.0.1'
PORT = 65433
CURVE = registry.get_curve('brainpoolP256r1')

print("----------------- ECC SERVER -----------------")

print("Menghasilkan kunci Private dan Public ECC untuk Server...")
server_priv_key = secrets.randbelow(CURVE.field.n)
server_pub_key = server_priv_key * CURVE.g
print("Kunci Server berhasil dibuat.\n")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
print(f"Server mendengarkan di {HOST}:{PORT}...")

while True:
    try:
        conn, addr = s.accept()
        with conn:
            print(f"\nTerhubung dengan klien baru: {addr}")
            
            # 1. Terima public key client & kirim public key server
            client_pub_key = pickle.loads(conn.recv(4096))
            conn.sendall(pickle.dumps(server_pub_key))
            print(f"Pertukaran kunci publik dengan {addr} berhasil.")

            # 2. Hitung shared key
            shared_key = server_priv_key * client_pub_key
            
            # --- KEY DERIVATION ---
            key_material = shared_key.x.to_bytes(32, 'big')
            aes_key = SHA256.new(key_material).digest()
            # ------------------------------------

            # 3. Terima pesan terenkripsi dari client
            encrypted_package = conn.recv(4096)
            encrypted_data = pickle.loads(encrypted_package)
            
            # --- DEKRIPSI AES-GCM ---
            nonce = encrypted_data['nonce']
            tag = encrypted_data['tag']
            ciphertext = encrypted_data['ciphertext']

            start_time = time.perf_counter()
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')
            end_time = time.perf_counter()
            # --------------------------------------
            
            computation_delay = (end_time - start_time) * 1000

            print(f"Pesan berhasil didekripsi: '{decrypted_message}'")
            print(f"-> Waktu komputasi (dekripsi AES): {computation_delay:.4f} ms")

            conn.sendall(b'OK')

    except Exception as e:
        print(f"[SERVER ERROR] Terjadi kesalahan: {e}")
        break