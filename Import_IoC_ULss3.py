import os
import csv
import re
import zipfile
import shutil
import tkinter as tk
from tkinter import filedialog

PASSWORD = b"cnaipic"


# ---------------------------------------------------------
# Estrazione ZIP
# ---------------------------------------------------------
def extract_zip(zip_path, extract_to):
    """Estrae un file ZIP, anche se protetto da password."""
    with zipfile.ZipFile(zip_path, "r") as z:
        try:
            z.extractall(path=extract_to, pwd=PASSWORD)
        except RuntimeError:
            z.extractall(path=extract_to)


def find_all_zips(directory):
    """Trova tutti i file ZIP nella cartella e sottocartelle."""
    zips = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.lower().endswith(".zip"):
                zips.append(os.path.join(root, f))
    return zips


def delete_json_files(directory):
    """Elimina tutti i file .json."""
    count = 0
    for root, _, files in os.walk(directory):
        for f in files:
            if f.lower().endswith(".json"):
                os.remove(os.path.join(root, f))
                count += 1
    print(f"[✓] Rimossi {count} file JSON.")


# ---------------------------------------------------------
# Estrazione CSV e classificazione IoC
# ---------------------------------------------------------
def extract_csv_column_e(directory):
    """
    Cerca tutti i CSV e suddivide la colonna E in:
    - IPv4 / IPv6
    - URL / Domini
    - Filenames + SHA-256
    """

    csv_files = []
    ipv_list = []
    url_domain_list = []
    file_hash_list = []

    # Regex robuste
    ipv4_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    ipv6_regex = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b")

    url_regex = re.compile(r"\bhttps?://[^\s/$.?#].[^\s]*\b")
    domain_regex = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

    sha256_regex = re.compile(r"\b[a-fA-F0-9]{64}\b")
    filename_regex = re.compile(r"\b[\w\-. ]+\.[A-Za-z0-9]{1,8}\b")

    # 1) Trova CSV
    for root, _, files in os.walk(directory):
        for f in files:
            if f.lower().endswith(".csv"):
                csv_files.append(os.path.join(root, f))

    if not csv_files:
        print("[!] Nessun file CSV trovato.")
        return

    print(f"[+] Trovati {len(csv_files)} CSV")

    # 2) Estrazione dai CSV
    for file_path in csv_files:
        print(f"[+] Elaboro: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as csvfile:
                reader = csv.reader(csvfile)
                next(reader, None)  # salta intestazione

                for row in reader:
                    if len(row) <= 4:
                        continue

                    value = row[4].strip()
                    if value == "":
                        continue

                    # Classificazione IoC
                    if ipv4_regex.fullmatch(value) or ipv6_regex.fullmatch(value):
                        ipv_list.append(value)
                        continue

                    if url_regex.fullmatch(value):
                        url_domain_list.append(value)
                        continue

                    if domain_regex.fullmatch(value):
                        url_domain_list.append(value)
                        continue

                    if sha256_regex.fullmatch(value):
                        file_hash_list.append(value)
                        continue

                    if filename_regex.fullmatch(value):
                        file_hash_list.append(value)
                        continue

        except Exception as e:
            print(f"[!] Errore leggendo {file_path}: {e}")

    # 3) Scrittura file finali
    ip_file = os.path.join(directory, "IP.txt")
    url_file = os.path.join(directory, "URL_Domain.txt")
    file_file = os.path.join(directory, "Filename_SHA256.txt")

    with open(ip_file, "w", encoding="utf-8") as f:
        f.write("\n".join(ipv_list))

    with open(url_file, "w", encoding="utf-8") as f:
        f.write("\n".join(url_domain_list))

    with open(file_file, "w", encoding="utf-8") as f:
        f.write("\n".join(file_hash_list))

    print("[✓] File creati:")
    print(f"    → {ip_file}    ({len(ipv_list)} elementi)")
    print(f"    → {url_file}   ({len(url_domain_list)} elementi)")
    print(f"    → {file_file}  ({len(file_hash_list)} elementi)")


# ---------------------------------------------------------
# Pipeline completa
# ---------------------------------------------------------
def fully_extract_all_zips(start_zip, output_dir="estrazione_finale"):
    # Pulisce la cartella
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    print(f"[+] Estrazione iniziale: {start_zip}")
    extract_zip(start_zip, output_dir)

    # Estrazione ricorsiva
    while True:
        zips = find_all_zips(output_dir)
        if not zips:
            break
        print(f"[+] Trovati {len(zips)} ZIP annidati → estrazione...")
        for z in zips:
            extract_zip(z, os.path.dirname(z))
            os.remove(z)

    delete_json_files(output_dir)
    extract_csv_column_e(output_dir)


# ---------------------------------------------------------
# Main con finestra Tkinter
# ---------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    print("Seleziona il file ZIP iniziale...")

    percorso_zip_iniziale = filedialog.askopenfilename(
        title="Seleziona ZIP",
        filetypes=[("Archivi ZIP", "*.zip")]
    )

    if not percorso_zip_iniziale:
        print("Nessun file selezionato.")
    else:
        fully_extract_all_zips(percorso_zip_iniziale)
