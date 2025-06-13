# ecc_client.py

import socket
import time
import pickle
from tinyec import registry
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Konfigurasi Client
HOST = '127.0.0.1'
PORT = 65433
NUM_SAMPLES = 100
CURVE = registry.get_curve('brainpoolP256r1')

# --- TAMBAHKAN PLAINTEXT DI SINI ---
PLAINTEXT_MESSAGE = "AWAWAWAWAWAWAWAWAW"
# -----------------------------------

print("----------------- ECC CLIENT -----------------")

computation_delays = []
communication_delays = []

try:
    print(f"Memulai pengujian dengan {NUM_SAMPLES} sampel...")
    print(f"Ukuran Plaintext: {len(PLAINTEXT_MESSAGE.encode('utf-8'))} bytes")

    for i in range(NUM_SAMPLES):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # 1. Buat kunci & lakukan pertukaran kunci publik
            client_priv_key = secrets.randbelow(CURVE.field.n)
            client_pub_key = client_priv_key * CURVE.g
            
            s.sendall(pickle.dumps(client_pub_key))
            server_pub_key = pickle.loads(s.recv(4096))
            
            # 2. Hitung shared key
            shared_key = client_priv_key * server_pub_key
            
            # --- KEY DERIVATION ---
            key_material = shared_key.x.to_bytes(32, 'big')
            aes_key = SHA256.new(key_material).digest()
            # ------------------------------------

            # --- PENGUKURAN COMPUTATIONAL DELAY (ENKRIPSI AES) ---
            start_comp = time.perf_counter()
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(PLAINTEXT_MESSAGE.encode('utf-8'))
            nonce = cipher_aes.nonce
            end_comp = time.perf_counter()
            
            comp_delay_ms = (end_comp - start_comp) * 1000
            computation_delays.append(comp_delay_ms)
            
            # --- PENGUKURAN COMMUNICATION DELAY (PENGIRIMAN CIPHERTEXT) ---
            encrypted_package = pickle.dumps({'nonce': nonce, 'tag': tag, 'ciphertext': ciphertext})
            
            start_comm = time.perf_counter()
            s.sendall(encrypted_package)
            s.recv(1024) # Tunggu konfirmasi 'OK'
            end_comm = time.perf_counter()
            
            comm_delay_ms = (end_comm - start_comm) * 1000
            communication_delays.append(comm_delay_ms)
            
            print(f"Sampel {i + 1}/{NUM_SAMPLES} | Comp Delay: {comp_delay_ms:.4f} ms | Comm Delay: {comm_delay_ms:.4f} ms")
            time.sleep(0.05)

except Exception as e:
    print(f"[CLIENT ERROR] Terjadi kesalahan: {e}")

finally:
    if computation_delays and communication_delays:
        avg_comp = sum(computation_delays) / len(computation_delays)
        avg_comm = sum(communication_delays) / len(communication_delays)
        
        print("\n----------------- HASIL RATA-RATA (ECC + AES) -----------------")
        print(f"Total Sampel Diambil\t: {len(computation_delays)}")
        print(f"Ukuran Plaintext\t: {len(PLAINTEXT_MESSAGE.encode('utf-8'))} bytes")
        print(f"Rata-rata Delay Komputasi (Enkripsi AES)\t: {avg_comp:.4f} ms")
        print(f"Rata-rata Delay Komunikasi (Ciphertext)\t: {avg_comm:.4f} ms")
        print("---------------------------------------------------------")