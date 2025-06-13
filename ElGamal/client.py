import socket
import time
import pickle
import elgamal

HOST = '127.0.0.1'
PORT = 65432
NUM_SAMPLES = 100

# --- Change The Message Size here for testing---
PLAINTEXT_MESSAGE = "AWAWAWAWAWAWAWAWAW"

print("----------------- CLIENT -----------------")

# List untuk menyimpan hasil pengukuran
computation_delays = []
communication_delays = []

try:
    # Membuat koneksi dengan server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Terhubung dengan server di {HOST}:{PORT}")

        # 1. Terima public key dari server
        pickled_public_key = s.recv(4096)
        public_key = pickle.loads(pickled_public_key)
        print(f"Kunci publik diterima dari server (bit length: {public_key.iNumBits}).\n")

        print(f"Memulai pengujian dengan {NUM_SAMPLES} sampel...")
        print(f"Ukuran Plaintext: {len(PLAINTEXT_MESSAGE.encode('utf-8'))} bytes")
        
        # 2. Loop untuk pengujian sebanyak NUM_SAMPLES
        for i in range(NUM_SAMPLES):
            # --- PENGUKURAN COMPUTATIONAL DELAY (ENKRIPSI) ---
            start_comp = time.perf_counter()
            cipher_text = elgamal.encrypt(public_key, PLAINTEXT_MESSAGE)
            end_comp = time.perf_counter()
            
            comp_delay_ms = (end_comp - start_comp) * 1000
            computation_delays.append(comp_delay_ms)
            
            # --- PENGUKURAN COMMUNICATION DELAY (ROUND-TRIP TIME) ---
            start_comm = time.perf_counter()
            # Kirim ciphertext ke server
            s.sendall(cipher_text.encode('utf-8'))
            # Tunggu konfirmasi 'OK' dari server
            confirmation = s.recv(1024)
            end_comm = time.perf_counter()

            if confirmation == b'OK':
                comm_delay_ms = (end_comm - start_comm) * 1000
                communication_delays.append(comm_delay_ms)

            # Tampilkan progress
            print(f"Sampel {i + 1}/{NUM_SAMPLES} | Comp Delay: {comp_delay_ms:.2f} ms | Comm Delay: {comm_delay_ms:.2f} ms")
            time.sleep(0.1) # Beri jeda singkat antar sampel

except ConnectionRefusedError:
    print("[ERROR] Koneksi ditolak. Pastikan server.py sudah berjalan.")
except Exception as e:
    print(f"[ERROR] Terjadi kesalahan: {e}")

finally:
    # 3. Hitung dan tampilkan rata-rata
    if computation_delays and communication_delays:
        avg_comp = sum(computation_delays) / len(computation_delays)
        avg_comm = sum(communication_delays) / len(communication_delays)
        
        print("\n----------------- HASIL RATA-RATA -----------------")
        print(f"Total Sampel Diambil\t: {len(computation_delays)}")
        # --- DIKOREKSI ---
        print(f"Ukuran Plaintext\t: {len(PLAINTEXT_MESSAGE.encode('utf-8'))} bytes")
        print(f"Rata-rata Delay Komputasi (Enkripsi)\t: {avg_comp:.4f} ms")
        print(f"Rata-rata Delay Komunikasi (Round-Trip)\t: {avg_comm:.4f} ms")
        print("-------------------------------------------------")