import streamlit as st
import mysql.connector
from PIL import Image
from mysql.connector import Error
from PyPDF2 import PdfReader, PdfWriter
import io
import os
import hashlib
import re
from super_enkripsi import *

# Koneksi ke Database MySQL
def create_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",  # Ubah sesuai konfigurasi MySQL Anda
        password="",  # Ubah sesuai konfigurasi MySQL Anda
        database="database_soal"
    )

# Fungsi untuk hashing password
def hash_password(password):
    hash_object = hashlib.sha256(password.encode())
    return hash_object.hexdigest()

# Fungsi untuk mendaftarkan pengguna
def register(username, password):
    hashed_password = hash_password(password)
    try:
        register_user(username, hashed_password)
    except ValueError as e:
        raise ValueError(f"Registrasi gagal: {e}")
    except Exception as e:
        raise Exception(f"Terjadi kesalahan: {e}")

# Fungsi untuk memverifikasi login pengguna
def login(username, password):
    hashed_password = hash_password(password)
    try:
        return verify_login(username, hashed_password)
    except Exception as e:
        raise Exception(f"Login gagal: {e}")

def register_user(username, hashed_password):
    try:
        connection = create_connection()
        cursor = connection.cursor()
        query = "INSERT INTO user (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))
        connection.commit()
    except mysql.connector.IntegrityError:
        raise ValueError("Username sudah digunakan. Coba username lain.")
    except Error as e:
        raise Exception(f"Terjadi kesalahan: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Fungsi untuk memverifikasi login pengguna
def verify_login(username, hashed_password):
    try:
        connection = create_connection()
        cursor = connection.cursor()
        query = "SELECT password FROM user WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        if result and result[0] == hashed_password:
            return True
        else:
            return False
    except Error as e:
        raise Exception(f"Terjadi kesalahan: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Membuat tabel (hanya diperlukan sekali)
def create_table():
    try:
        connection = create_connection()
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_pdf (
            id INT AUTO_INCREMENT PRIMARY KEY,
            kode_soal TEXT NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            file_data LONGBLOB NOT NULL,
            encryption_key VARCHAR(255) NOT NULL
        )
        """)
        connection.commit()
    except Error as e:
        st.error(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def hide_message(image, message):
    encoded_image = image.copy()
    binary_message = ''.join([format(ord(i), "08b") for i in message]) + '11111111'
    pixels = encoded_image.load()

    idx = 0
    for row in range(image.height):
        for col in range(image.width):
            if idx < len(binary_message):
                r, g, b = pixels[col, row]
                r = (r & ~1) | int(binary_message[idx])  # Encode bit ke LSB Red
                pixels[col, row] = (r, g, b)
                idx += 1
    return encoded_image

# Fungsi untuk membaca pesan dari gambar
def reveal_message(image):
    pixels = image.load()
    binary_message = ""
    for row in range(image.height):
        for col in range(image.width):
            r, _, _ = pixels[col, row]
            binary_message += str(r & 1)

            if binary_message[-8:] == "11111111":
                return ''.join([chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message)-8, 8)])
    return "Tidak ada pesan tersembunyi."

# Fungsi untuk menyimpan data ke database
def save_to_db(image):
    conn = create_connection()
    cursor = conn.cursor()
    image_byte_arr = io.BytesIO()
    image.save(image_byte_arr, format='PNG')
    image_blob = image_byte_arr.getvalue()

    query = "INSERT INTO stego_image (image) VALUES (%s)"
    cursor.execute(query, (image_blob,))
    conn.commit()
    st.success("Gambar dan pesan berhasil disimpan ke database!")

# Fungsi untuk mengambil gambar dari database
def fetch_images_from_db():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, image FROM stego_image")
    return cursor.fetchall()

# Fungsi untuk mengunggah PDF ke database
def upload_pdf(kode_soal, file, encryption_key):
    try:
        connection = create_connection()
        cursor = connection.cursor()
        encrypted_data = encrypt_pdf(file, encryption_key)
        kode_soal = super_encrypt(kode_soal)
        cursor.execute(
            "INSERT INTO encrypted_pdf (kode_soal, file_name, file_data, encryption_key) VALUES (%s, %s, %s, %s)",
            (kode_soal, file.name, encrypted_data, encryption_key)
        )
        connection.commit()
        st.success("File berhasil diunggah!")
    except Error as e:
        st.error(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Fungsi untuk mengenkripsi PDF
def encrypt_pdf(file, key):
    pdf_reader = PdfReader(file)
    pdf_writer = PdfWriter()

    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    pdf_writer.encrypt(user_pwd=key, owner_pwd=key, use_128bit=True)

    buffer = io.BytesIO()
    pdf_writer.write(buffer)
    buffer.seek(0)
    return buffer.read()

# Fungsi untuk mendekripsi PDF
def decrypt_pdf(encrypted_data, key):
    try:
        pdf_reader = PdfReader(io.BytesIO(encrypted_data))
        pdf_reader.decrypt(key)
        
        pdf_writer = PdfWriter()
        for page in pdf_reader.pages:
            pdf_writer.add_page(page)
        
        buffer = io.BytesIO()
        pdf_writer.write(buffer)
        buffer.seek(0)
        return buffer.read()
    except Exception as e:
        st.error(f"Error during decryption: {e}")
        return None

# Fungsi untuk mendapatkan daftar file dari database
def fetch_files():
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, file_name, kode_soal FROM encrypted_pdf")
        return cursor.fetchall()
    except Error as e:
        st.error(f"Error: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Fungsi untuk mengunduh file dari database
def download_file(file_id, input_key):
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT file_name, file_data, encryption_key FROM encrypted_pdf WHERE id = %s", (file_id,))
        file_record = cursor.fetchone()

        if file_record:
            if file_record['encryption_key'] == input_key:
                st.success("Kunci valid! File siap diunduh.")
                st.download_button(
                    label="Unduh File",
                    data=file_record['file_data'],
                    file_name=file_record['file_name'],
                    mime="application/pdf"
                )
            else:
                st.error("Kunci yang Anda masukkan salah!")
        else:
            st.error("File tidak ditemukan.")
    except Error as e:
        st.error(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Fungsi untuk mendekripsi dan mengunduh file dari database
def decrypt_and_download_file(file_id, input_key):
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT file_name, file_data, encryption_key FROM encrypted_pdf WHERE id = %s", (file_id,))
        file_record = cursor.fetchone()

        if file_record:
            if file_record['encryption_key'] == input_key:
                st.success("Kunci valid! File sedang didekripsi...")
                decrypted_data = decrypt_pdf(file_record['file_data'], input_key)
                
                if decrypted_data:
                    st.download_button(
                        label="Unduh File Dekripsi",
                        data=decrypted_data,
                        file_name=file_record['file_name'],
                        mime="application/pdf"
                    )
                else:
                    st.error("Gagal mendekripsi file.")
            else:
                st.error("Kunci yang Anda masukkan salah!")
        else:
            st.error("File tidak ditemukan.")
    except Error as e:
        st.error(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def login_page():
    st.title("GATOTKACA")
    st.subheader("Sistem Pengamanan Soal Ujian")
    st.markdown("### Login")
    
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    
    if st.button("MASUK"):
        if username and password:
            try:
                if login(username, password):
                    st.session_state["logged_in"] = True
                    st.session_state["username"] = username
                    st.rerun() 
                else:
                    st.error("Nama pengguna atau kata sandi salah!")
            except Exception as e:
                st.error(f"Terjadi kesalahan: {e}")
        else:
            st.warning("Silakan masukkan nama pengguna dan kata sandi!")

    if st.button("Belum punya akun? Daftar di sini"):
        st.session_state["show_register"] = True
        st.rerun() 

# Fungsi untuk halaman registrasi
def register_page():
    st.title("GATOTKACA")
    st.subheader("Sistem Pengamanan Soal Ujian")
    st.markdown("### Registration")

    username = st.text_input("Username", key="register_username")
    password = st.text_input("Password", type="password", key="register_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
    
    if st.button("Daftar"):
        if username and password and confirm_password:
            if password == confirm_password:
                try:
                    register(username, password)
                    st.success("Registrasi berhasil! Silakan login.")
                    st.session_state["show_register"] = False
                    st.rerun()
                except ValueError as e:
                    st.error(f"Registrasi gagal: {e}")
                except Exception as e:
                    st.error(f"Terjadi kesalahan: {e}")
            else:
                st.error("Kata sandi dan konfirmasi kata sandi tidak cocok!")
        else:
            st.warning("Harap isi semua kolom!")

    if st.button("Sudah punya akun? Login di sini"):
        st.session_state["show_register"] = False
        st.rerun()  


# Streamlit UI
def dashboard_page():
    # Tombol logout di sidebar
    if st.sidebar.button("Keluar"):
        st.session_state["logged_in"] = False
        st.rerun()

    username = st.session_state.get('username', 'Pengguna')

    # Membersihkan username (mengambil hanya huruf dan mengubah huruf pertama menjadi kapital)
    clean_username = re.sub(r'[^a-zA-Z]', '', username).capitalize()

    st.title(f"Selamat Datang, {clean_username}!")
    st.subheader("GATOTKACA - Sistem Pengamanan Soal Ujian")
    st.text("\n\n")
    

    menu = ["Upload PDF", "Daftar & Unduh PDF", "Dekripsi PDF", "Steganografi"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Upload PDF":
        st.header("Menu Enkripsi Soal")
        st.text("Masukkan Kode Soal Ujian")
        st.text("format (Nama Matkul-semester-tahunSoal)")
        exam_code = st.text_input("Contoh : Matematika-5-2022")

        st.subheader("Enkripsi File PDF")
        uploaded_file = st.file_uploader("Pilih file PDF", type=["pdf"])
        encryption_key = st.text_input("Masukkan kunci enkripsi", type="password")
        

        if st.button("Unggah"):
            if uploaded_file and encryption_key:
                upload_pdf(exam_code, uploaded_file, encryption_key)
            else:
                st.warning("Harap unggah file PDF dan masukkan kunci enkripsi.")

    elif choice == "Daftar & Unduh PDF":
        st.header("Daftar File PDF")
        files = fetch_files()

        if files:
            for file in files:
                kode = file['kode_soal']
                kode = super_decrypt(kode)
                st.write(f"Kode: {kode}")
                st.write(f"Nama: {file['file_name']}")
                input_key = st.text_input("Masukkan kunci untuk unduh", type="password", key=f"key_{file['id']}")

                if st.button(f"Validasi & Unduh (ID: {file['id']})"):
                    download_file(file['id'], input_key)
        else:
            st.info("Tidak ada file yang tersedia.")

    elif choice == "Dekripsi PDF":
        st.header("Dekripsi File PDF")
        menu = st.selectbox("MENU",["Dekripsi PDF yang ada di Database", "Dekripsi PDF dari File Lokal"])
        files = fetch_files()
        if menu == "Dekripsi PDF yang ada di Database":
            if files:
                for file in files:
                    kode = file['kode_soal']
                    kode = super_decrypt(kode)
                    st.write(f"Kode: {kode}")
                    st.write(f"Nama: {file['file_name']}")
                    input_key = st.text_input("Masukkan kunci untuk dekripsi", type="password", key=f"decrypt_key_{file['id']}")

                    if st.button(f"Validasi & Dekripsi (Kode: {kode})"):
                        decrypt_and_download_file(file['id'], input_key)
            else:
                st.info("Tidak ada file yang tersedia.")
        elif menu == "Dekripsi PDF dari File Lokal":
            st.subheader("Dekripsi dari Komputer")
            uploaded_pdf = st.file_uploader("Unggah File PDF Terenkripsi", type=["pdf"])
            decryption_key = st.text_input("Masukkan kunci dekripsi untuk file lokal", type="password")

            if st.button("Dekripsi File Lokal"):
                if uploaded_pdf and decryption_key:
                    try:
                        pdf_data = uploaded_pdf.read()
                        decrypted_data = decrypt_pdf(pdf_data, decryption_key)

                        if decrypted_data:
                            st.success("File berhasil didekripsi!")
                            st.download_button(
                                label="Unduh File Dekripsi",
                                data=decrypted_data,
                                file_name="decrypted_" + uploaded_pdf.name,
                                mime="application/pdf"
                            )
                        else:
                            st.error("Gagal mendekripsi file. Pastikan kunci yang dimasukkan benar.")
                    except Exception as e:
                        st.error(f"Terjadi kesalahan: {e}")
                else:
                    st.warning("Harap unggah file dan masukkan kunci dekripsi.")

    elif choice == "Steganografi":

        menu = st.selectbox("Menu", ["Menyimpan Pesan", "Melihat Pesan"])
        
        if menu == "Menyimpan Pesan":
            st.header("Menyisipkan Pesan ke dalam Gambar")
            uploaded_image = st.file_uploader("Unggah Gambar", type=["png", "jpg", "jpeg"])
            message = st.text_area("Pesan yang akan disisipkan")
            pesan = super_encrypt(message)
            if uploaded_image and message:
                image = Image.open(uploaded_image).convert("RGB")
                encoded_image = hide_message(image, pesan)

                st.image(encoded_image, caption="Gambar dengan pesan tersembunyi")

                if st.button("Simpan ke Database"):
                    save_to_db(encoded_image)

                image_byte_arr = io.BytesIO()
                encoded_image.save(image_byte_arr, format="PNG")
                st.download_button(
                    label="Download Gambar dengan Pesan",
                    data=image_byte_arr.getvalue(),
                    file_name="stego_image.png",
                    mime="image/png"
                )

        elif menu == "Melihat Pesan":
            st.header("Melihat Pesan dari Gambar")

            source_option = st.radio("Pilih Sumber Gambar", ["Unggah Gambar", "Dari Database"])

            if source_option == "Unggah Gambar":
        
                uploaded_image = st.file_uploader("Unggah Gambar", type=["png", "jpg", "jpeg"])
        
                if uploaded_image:
                    image = Image.open(uploaded_image).convert("RGB")
                    st.image(image, caption="Gambar yang diunggah")

                    if st.button("Lihat Pesan"):
                        message = reveal_message(image)
                        pesan = super_decrypt(message)
                        st.write(f"Pesan: {pesan}")

            elif source_option == "Dari Database":
                images = fetch_images_from_db()
                if images:
                    image_options = {f"Gambar {img[0]}": img for img in images}
                    selected_image = st.selectbox("Pilih Gambar", list(image_options.keys()))

                    if selected_image:
                        image_id, image_blob = image_options[selected_image]
                        image = Image.open(io.BytesIO(image_blob))
                        st.image(image, caption=f"Gambar {image_id}")

                        if st.button("Lihat Pesan"):
                            message = reveal_message(image)
                            pesan = super_decrypt(message)
                            st.write(f"Pesan: {pesan}")
                else:
                    st.write("Tidak ada gambar dalam database.")
def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "show_register" not in st.session_state:
        st.session_state["show_register"] = False

    if st.session_state["logged_in"]:
        create_table()
        dashboard_page()
    elif st.session_state["show_register"]:
        register_page()
    else:
        login_page()

# Jalankan aplikasi
if __name__ == "__main__":
    main()

