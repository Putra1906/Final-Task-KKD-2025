# server.py

import socket
import time
import pickle  # Untuk mengirim objek kunci melalui socket
import elgamal # Mengimpor file elgamal.py yang sudah kita siapkan

# Konfigurasi Server
HOST = '127.0.0.1'  # Alamat localhost
PORT = 65432

print("----------------- SERVER -----------------")

# 1. Generate Kunci ElGamal (hanya sekali saat server dimulai)
print("Menghasilkan kunci Public dan Private ElGamal...")
# Untuk mempercepat proses testing, kita gunakan bit yang tidak terlalu besar.
# Ubah iNumBits ke 256 atau 512 untuk keamanan lebih tinggi (tapi lebih lambat).
keys = elgamal.generate_keys(iNumBits=128, iConfidence=32)
private_key = keys['privateKey']
public_key = keys['publicKey']
print("Kunci berhasil dibuat.")
print(f"Prime (p) bit length: {public_key.iNumBits}\n")

# Membuat socket server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server mendengarkan di {HOST}:{PORT}...")
    
    # --- DIKOREKSI: Tambahkan loop while True agar server bisa menerima banyak koneksi ---
    while True:
        try:
            # Menerima koneksi dari client
            conn, addr = s.accept()
            with conn:
                print(f"\nTerhubung dengan {addr}")
                
                # 2. Kirim public key ke client
                # Kita gunakan pickle untuk mengubah objek 'PublicKey' menjadi byte
                pickled_public_key = pickle.dumps(public_key)
                conn.sendall(pickled_public_key)
                print("Kunci publik telah dikirim ke klien.")

                # Loop untuk menerima pesan dari client
                while True:
                    # 3. Terima ciphertext dari client
                    data = conn.recv(4096) # buffer size 4096 bytes
                    if not data:
                        print(f"Koneksi dengan {addr} ditutup.")
                        break # Jika tidak ada data, koneksi ditutup oleh client

                    ciphertext = data.decode('utf-8')
                    print(f"Menerima ciphertext: ...{ciphertext[-50:]}") # Tampilkan 50 karakter terakhir

                    # 4. Ukur Waktu Dekripsi (Computational Delay)
                    start_time = time.perf_counter()
                    decrypted_message = elgamal.decrypt(private_key, ciphertext)
                    end_time = time.perf_counter()
                    
                    computation_delay = (end_time - start_time) * 1000 # dalam milidetik
                    
                    print(f"Pesan berhasil didekripsi: '{decrypted_message}'")
                    print(f"-> Waktu komputasi (dekripsi): {computation_delay:.4f} ms")

                    # 5. Kirim konfirmasi ke client agar RTT bisa diukur
                    conn.sendall(b'OK')
        except Exception as e:
            print(f"[SERVER ERROR] Terjadi kesalahan: {e}")
            # Lanjutkan loop untuk menerima koneksi baru
            continue