import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.ttk import Notebook
from PIL import Image, ImageTk, ImageStat
import exiftool
import subprocess
import base64
import os
import qrcode
import numpy as np
from pyzbar.pyzbar import decode
import hashlib
import struct
import binascii
import re
from PIL import ImageSequence  # Für Layer-Analyse
import pytesseract  # Für OCR
# Neue Registerkarte: Hexdump - Hexdump 
import binascii
import tkinter as tk
from tkinter import ttk

# Globale Variablen
FLAG_START = "SCD{"
FLAG_END = "}"

# Hauptfenster erstellen
root = tk.Tk()
root.title("Advanced Flag Finder")
root.geometry("1200x800")
root.configure(bg="white")  # Schlichtes Design: Weißer Hintergrund

# Modernes Design
style = ttk.Style()
style.theme_use("clam")  # Moderne Theme-Variante
style.configure("TLabel", background="white")
style.configure("TButton", background="white")
style.configure("TFrame", background="white")

# Notebook für Tabs
notebook = Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

# Tab 1: Flag Finder
tab_flag_finder = tk.Frame(notebook, bg="white")
notebook.add(tab_flag_finder, text="Flag Finder")

# Tab 2: Tools
tab_tools = tk.Frame(notebook, bg="white")
notebook.add(tab_tools, text="Tools")



# Label für den Status
status_label = ttk.Label(root, text="No image uploaded.", font=("Arial", 12), anchor="w", relief="sunken")
status_label.pack(side="bottom", fill="x", pady=5)

# Variablen für Custom-Pattern
pattern_start_var = tk.StringVar(value=FLAG_START)
pattern_end_var = tk.StringVar(value=FLAG_END)

# Variable für das hochgeladene Bild
image_path = None
preview_image = None

# Funktion zum Hochladen eines Bildes
def upload_image():
    global image_path
    image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.jpeg *.png *.xcf")])
    if image_path:
        status_label.config(text=f"Uploaded: {image_path}")
        check_for_flag()
        display_image_preview()
        display_hexdump()
        display_exif_info()
        display_file_text()  # Zeige den Dateiinhalt an
        open_in_editor()  # Öffne das Bild im Editor
        display_gimp_xcf_analysis()  # Zeige die GIMP XCF-Analyse an

# Funktion zur Anzeige des Bildes in der Vorschau
def display_image_preview():
    global preview_image
    try:
        img = Image.open(image_path)
        img.thumbnail((300, 300))  # Skaliere das Bild
        preview_image = ImageTk.PhotoImage(img)
        image_preview_label.config(image=preview_image)
    except Exception as e:
        print(f"Error displaying image preview: {e}")

# Funktion zur Flag-Suche
def check_for_flag():
    for method in methods:
        method_name = method["name"]
        result = method["function"](image_path)
        flag = extract_flag(result)  # Extrahiere die Flagge
        if flag:
            update_table(method_name, "success", flag)  # Aktualisiere die Tabelle mit der Flagge
            print(f"Flag found in {method_name}: {flag}")
        else:
            update_table(method_name, "error", "")  # Keine Flagge gefunden

# Funktion zur Aktualisierung der Tabelle
def update_table(method_name, status, flag_text):
    for row in table_rows:
        if row[0]["text"] == method_name:
            row[1].config(text=status.capitalize(), foreground="green" if status == "success" else "red")
            row[2].config(text=flag_text if flag_text else "")

# Funktion zur Extraktion der Flagge
def extract_flag(result):
    if not result or not isinstance(result, str):  # Ignoriere ungültige Ergebnisse
        return ""
    start = result.find(FLAG_START)
    end = result.find(FLAG_END, start)
    if start != -1 and end != -1:
        return result[start:end + len(FLAG_END)]  # Korrekte Endposition
    return ""

# GUI-Erstellung für Tab 1 Tabelle (Überprüfung der Funktionen)
frame_upload = ttk.Frame(tab_flag_finder)
frame_upload.pack(pady=10)

upload_button = ttk.Button(frame_upload, text="Upload Image", command=upload_image)
upload_button.pack(pady=10)

# Bildvorschau
image_preview_label = ttk.Label(tab_flag_finder, text="Image Preview", font=("Arial", 12))
image_preview_label.pack(pady=10)

# Scrollbare Tabelle für die Methoden
table_frame = ttk.Frame(tab_flag_finder)
table_frame.pack(pady=10)

canvas = tk.Canvas(table_frame, width=1100, height=500, bg="white")
scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=canvas.yview)
scrollable_frame = ttk.Frame(canvas)

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Neue Funktionen

# Metadaten überprüfen
def check_metadata(path):
    with exiftool.ExifToolHelper() as et:
        try:
            metadata = et.get_metadata(path)
            for data in metadata:
                for key, value in data.items():
                    if isinstance(value, str) and FLAG_START in value and FLAG_END in value:
                        return value
        except Exception as e:
            return f"Error checking metadata: {e}"  # Entferntes <button>-Tag
    return None

# Steganographie (zsteg) überprüfen
def check_steganography(path):
    try:
        result = subprocess.run(["zsteg", path], capture_output=True, text=True)
        output = result.stdout + result.stderr
        if FLAG_START in output and FLAG_END in output:
            return output.strip()
    except Exception as e:
        print(f"Error running zsteg: {e}")
    return None

# Am Anfang/Ende der Datei überprüfen
def check_start_end(path):
    try:
        with open(path, "rb") as f:
            content = f.read().decode(errors="ignore")
            if FLAG_START in content and FLAG_END in content:
                start = content.find(FLAG_START)
                end = content.find(FLAG_END) + len(FLAG_END)
                return content[start:end]
    except Exception as e:
        print(f"Error checking start/end of file: {e}")
    return None

# Base64-Codierung in Metadaten überprüfen
def check_base64(path):
    with exiftool.ExifToolHelper() as et:
        try:
            metadata = et.get_metadata(path)
            for data in metadata:
                for value in data.values():
                    if isinstance(value, str):
                        try:
                            decoded = base64.b64decode(value).decode(errors="ignore")
                            if FLAG_START in decoded and FLAG_END in decoded:
                                return decoded
                        except:
                            pass
        except Exception as e:
            print(f"Error checking base64: {e}")
    return None

# XOR-Verschlüsselung überprüfen
def check_xor(path):
    try:
        with open(path, "rb") as f:
            content = f.read()
            for key in range(256):
                decrypted = ''.join([chr(b ^ key) for b in content]).encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
                if FLAG_START in decrypted and FLAG_END in decrypted:
                    return decrypted
    except Exception as e:
        print(f"Error checking XOR: {e}")
    return None

# QR-Code scannen
def check_qr_code(path):
    try:
        img = Image.open(path)
        qr_codes = decode(img)
        for qr in qr_codes:
            if hasattr(qr, "data") and qr.data:
                data = qr.data.decode("utf-8", errors="ignore")
                if FLAG_START in data and FLAG_END in data:
                    return data
    except Exception as e:
        print(f"Error scanning QR code: {e}")
    return None

# LSB-Steganographie überprüfen
def check_lsb_steganography(path):
    try:
        img = Image.open(path).convert('RGB')
        pixels = np.array(img)
        binary_message = ""
        for row in pixels:
            for pixel in row:
                for color_channel in pixel:
                    binary_message += str(color_channel & 1)
                    if len(binary_message) % 8 == 0:
                        byte = chr(int(binary_message[-8:], 2))
                        if FLAG_START in binary_message and FLAG_END in binary_message:
                            return binary_message
    except Exception as e:
        print(f"Error checking LSB steganography: {e}")
    return None

# Hex-Dump-Analyse
def check_hex_dump(path):
    try:
        with open(path, "rb") as f:
            content = f.read()
            hex_dump = binascii.hexlify(content).decode()
            if FLAG_START in hex_dump and FLAG_END in hex_dump:
                return hex_dump
    except Exception as e:
        print(f"Error checking hex dump: {e}")
    return None

# EXIF-Tag-Spezifikation
def check_exif_tags(path):
    with exiftool.ExifToolHelper() as et:
        try:
            metadata = et.get_metadata(path)
            for tag in ["UserComment", "ImageDescription"]:
                if tag in metadata[0]:
                    value = metadata[0][tag]
                    if FLAG_START in value and FLAG_END in value:
                        return f"{tag}: {value}"
        except Exception as e:
            print(f"Error checking EXIF tags: {e}")
    return None

# Farbkanal-Separierung
def check_color_channels(path):
    try:
        img = Image.open(path).convert('RGB')
        r, g, b = img.split()
        channels = [r, g, b]
        for i, channel in enumerate(channels):
            channel_data = list(channel.getdata())
            for pixel in channel_data:
                if pixel > 200:  # Beispielbedingung
                    return f"Suspicious value in channel {i+1}: {pixel}"
    except Exception as e:
        print(f"Error checking color channels: {e}")
    return None

# Bild-Rotation
def check_image_rotation(path):
    try:
        for angle in [90, 180, 270]:
            img = Image.open(path).rotate(angle)
            pixels = list(img.getdata())
            for pixel in pixels:
                r, g, b = pixel
                if r > 200 and g < 50 and b < 50:  # Beispielbedingung
                    return f"Suspicious pixel after rotation {angle}°: {pixel}"
    except Exception as e:
        print(f"Error checking image rotation: {e}")
    return None

# Custom-Pattern-Suche
def check_custom_pattern(path):
    try:
        with open(path, "rb") as f:
            content = f.read().decode(errors="ignore")
            custom_pattern = pattern_start_var.get() + ".*?" + pattern_end_var.get()
            match = re.search(custom_pattern, content)
            if match:
                return match.group(0)
    except Exception as e:
        print(f"Error checking custom pattern: {e}")
    return None

# Dateisignatur-Überprüfung
def check_file_signature(path):
    try:
        with open(path, "rb") as f:
            header = f.read(10)
            if header.startswith(b"\xFF\xD8\xFF"):  # JPEG-Signatur
                return "Valid JPEG file."
            elif header.startswith(b"\x89PNG\r\n\x1A\n"):  # PNG-Signatur
                return "Valid PNG file."
            elif header.startswith(b"gimp"):  # GIMP XCF-Signatur
                return "Valid GIMP XCF file."
    except Exception as e:
        print(f"Error checking file signature: {e}")
    return None

# Textextraktion mit OCR
def check_ocr(path):
    try:
        img = Image.open(path)
        text = pytesseract.image_to_string(img)
        if FLAG_START in text and FLAG_END in text:
            return text
    except Exception as e:
        print(f"Error performing OCR: {e}")
    return None

# Kommentar-Analyse
def check_comments(path):
    try:
        with open(path, "rb") as f:
            content = f.read().decode(errors="ignore")
            if "Comment" in content or "comment" in content:
                return "Possible comment detected."
    except Exception as e:
        print(f"Error checking comments: {e}")
    return None

# Bildkompressions-Level
def check_compression_level(path):
    try:
        img = Image.open(path)
        if img.format == "JPEG":
            info = img.info
            if "quality" in info:
                return f"Compression Quality: {info['quality']}"
    except Exception as e:
        print(f"Error checking compression level: {e}")
    return None

# Layer-Analyse (GIMP XCF)
def check_layers(path):
    try:
        img = Image.open(path)
        layers = []
        for frame in ImageSequence.Iterator(img):
            layers.append(frame)
        if len(layers) > 1:
            return f"Detected {len(layers)} layers."
    except Exception as e:
        print(f"Error checking layers: {e}")
    return None

# Histogramm-Analyse
def check_histogram(path):
    try:
        img = Image.open(path).convert('RGB')
        histogram = img.histogram()
        if max(histogram) - min(histogram) > 1000:  # Beispielbedingung
            return "Unusual histogram detected."
    except Exception as e:
        print(f"Error checking histogram: {e}")
    return None

# Dateiintegrität-Überprüfung
def check_file_integrity(path):
    try:
        with open(path, "rb") as f:
            content = f.read()
            if not content:
                return "File appears to be corrupted."
    except Exception as e:
        print(f"Error checking file integrity: {e}")
    return None

# Pixel-Muster-Suche
def check_pixel_patterns(path):
    try:
        img = Image.open(path).convert('RGB')
        pixels = list(img.getdata())
        for i in range(len(pixels) - 1):
            if pixels[i] == pixels[i + 1]:  # Wiederholende Pixel
                return f"Repeating pixel pattern detected: {pixels[i]}"
    except Exception as e:
        print(f"Error checking pixel patterns: {e}")
    return None

# Dateiüberschreibung-Prüfung
def check_file_overwrite(path):
    try:
        with open(path, "rb") as f:
            content = f.read()
            if b"TRAILER" in content:  # Überschreibungs-Muster
                return "File overwrite pattern detected."
    except Exception as e:
        print(f"Error checking file overwrite: {e}")
    return None

# Pixelwert-Differenzanalyse
def check_pixel_differences(path):
    try:
        img = Image.open(path).convert('RGB')
        pixels = np.array(img)
        differences = np.abs(np.diff(pixels, axis=0)).sum(axis=2)
        if np.any(differences > 200):  # Hohe Differenzen
            return "High pixel difference detected."
    except Exception as e:
        print(f"Error checking pixel differences: {e}")
    return None

# Dateiheader-Überprüfung
def check_file_header(path):
    try:
        with open(path, "rb") as f:
            header = f.read(16)  # Lesen der ersten 16 Bytes
            if not header:
                return "Invalid file header."
    except Exception as e:
        print(f"Error checking file header: {e}")
    return None

# Textextraktion aus Metadaten (Erweitert)
def check_extended_metadata_text(path):
    with exiftool.ExifToolHelper() as et:
        try:
            metadata = et.get_metadata(path)
            for data in metadata:
                for key, value in data.items():
                    if isinstance(value, str) and len(value) > 10:  # Nur lange Strings analysieren
                        if FLAG_START in value and FLAG_END in value:
                            return f"{key}: {value}"
        except Exception as e:
            print(f"Error checking extended metadata text: {e}")
    return None

# Farbkanal-Korrelation
def check_color_correlation(path):
    try:
        img = Image.open(path).convert('RGB')
        r, g, b = img.split()
        correlation_rg = np.corrcoef(r.getdata(), g.getdata())[0, 1]
        correlation_rb = np.corrcoef(r.getdata(), b.getdata())[0, 1]
        correlation_gb = np.corrcoef(g.getdata(), b.getdata())[0, 1]
        if abs(correlation_rg) > 0.95 or abs(correlation_rb) > 0.95 or abs(correlation_gb) > 0.95:
            return "High color channel correlation detected."
    except Exception as e:
        print(f"Error checking color correlation: {e}")
    return None

# QR-Code mit Fehlerkorrektur
def check_qr_code_with_error_correction(path):
    try:
        img = Image.open(path)
        qr_codes = decode(img)
        for qr in qr_codes:
            if hasattr(qr, "data") and qr.data:
                data = qr.data.decode("utf-8", errors="ignore")
                if FLAG_START in data and FLAG_END in data:
                    return data
    except Exception as e:
        print(f"Error scanning QR code with error correction: {e}")
    return None

# Hash-Vergleich (Erweitert)
def check_hash_comparison(path):
    try:
        hash_value = hashlib.md5(open(path, 'rb').read()).hexdigest()
        known_hashes = ["d41d8cd98f00b204e9800998ecf8427e", "another_known_hash"]  # Beispielhashes
        if hash_value in known_hashes:
            return hash_value
    except Exception as e:
        print(f"Error checking hash comparison: {e}")
    return None

# GUI-Erstellung für Tab 1
methods = [
    {"name": "Metadata", "function": check_metadata},
    {"name": "Steganography (zsteg)", "function": check_steganography},
    {"name": "Start/End of File", "function": check_start_end},
    {"name": "Base64 in Metadata", "function": check_base64},
    {"name": "XOR Encryption", "function": check_xor},
    {"name": "QR Code", "function": check_qr_code},
    {"name": "LSB Steganography", "function": check_lsb_steganography},
    {"name": "Hex Dump Analysis", "function": check_hex_dump},
    {"name": "EXIF Tag Specification", "function": check_exif_tags},
    {"name": "Color Channel Separation", "function": check_color_channels},
    {"name": "Image Rotation", "function": check_image_rotation},
    {"name": "Custom Pattern Search", "function": check_custom_pattern},
    {"name": "File Signature Check", "function": check_file_signature},
    {"name": "OCR Text Extraction", "function": check_ocr},
    {"name": "Comment Analysis", "function": check_comments},
    {"name": "Compression Level", "function": check_compression_level},
    {"name": "Layer Analysis (GIMP XCF)", "function": check_layers},
    {"name": "Histogram Analysis", "function": check_histogram},
    {"name": "File Integrity Check", "function": check_file_integrity},
    {"name": "Pixel Pattern Search", "function": check_pixel_patterns},
    {"name": "File Overwrite Check", "function": check_file_overwrite},
    {"name": "Pixel Differences", "function": check_pixel_differences},
    {"name": "File Header Check", "function": check_file_header},
    {"name": "Extended Metadata Text", "function": check_extended_metadata_text},
    {"name": "Color Channel Correlation", "function": check_color_correlation},
    {"name": "QR Code with Error Correction", "function": check_qr_code_with_error_correction},
    {"name": "Hash Comparison (Extended)", "function": check_hash_comparison},
    # Fügen Sie hier weitere Funktionen hinzu...
]

# Erstellen der Scrollbaren Tabelle
table_rows = []
for i, method in enumerate(methods):
    method_label = ttk.Label(scrollable_frame, text=method["name"], width=30, anchor="w", font=("Arial", 10))
    status_label = ttk.Label(scrollable_frame, text="", width=15, anchor="center", font=("Arial", 10))
    flag_label = ttk.Label(scrollable_frame, text="", width=40, anchor="w", font=("Arial", 10))
    method_label.grid(row=i, column=0, padx=5, pady=2, sticky="w")
    status_label.grid(row=i, column=1, padx=5, pady=2, sticky="w")
    flag_label.grid(row=i, column=2, padx=5, pady=2, sticky="w")
    table_rows.append((method_label, status_label, flag_label))

# GUI-Erstellung für Tab 2 Tools
frame_custom = ttk.Frame(tab_tools)
frame_custom.pack(pady=10)

label_custom = ttk.Label(frame_custom, text="Custom Pattern Matching", font=("Arial", 12))
label_custom.pack(pady=10)

entry_start = ttk.Entry(frame_custom, textvariable=pattern_start_var, font=("Arial", 10))
entry_start.pack(pady=5)
entry_start.insert(0, "Enter start pattern")

entry_end = ttk.Entry(frame_custom, textvariable=pattern_end_var, font=("Arial", 10))
entry_end.pack(pady=5)
entry_end.insert(0, "Enter end pattern")

button_apply = ttk.Button(frame_custom, text="Apply Patterns", command=lambda: apply_patterns(pattern_start_var.get(), pattern_end_var.get()))
button_apply.pack(pady=10)

# Neue Registerkarte: Bildeditor
tab_editor = tk.Frame(notebook, bg="white")
notebook.add(tab_editor, text="Image Editor")

# Bildvorschau im Editor
editor_image_label = ttk.Label(tab_editor, text="Edited Image Preview", font=("Arial", 12))
editor_image_label.pack(pady=10)

# Funktion zum Öffnen des Bildes im Editor
def open_in_editor():
    global editor_image
    try:
        img = Image.open(image_path)
        img.thumbnail((500, 500))  # Skaliere das Bild
        editor_image = ImageTk.PhotoImage(img)
        editor_image_label.config(image=editor_image)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open image in editor: {e}")

# Funktion zum Drehen des Bildes nach links (90° gegen den Uhrzeigersinn)
def rotate_left():
    global editor_image
    try:
        img = Image.open(image_path)
        img = img.rotate(90, expand=True)  # Drehen um 90 Grad nach links
        img.thumbnail((500, 500))  # Skaliere das Bild
        editor_image = ImageTk.PhotoImage(img)
        editor_image_label.config(image=editor_image)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to rotate image left: {e}")

# Funktion zum Drehen des Bildes nach rechts (90° im Uhrzeigersinn)
def rotate_right():
    global editor_image
    try:
        img = Image.open(image_path)
        img = img.rotate(-90, expand=True)  # Drehen um 90 Grad nach rechts
        img.thumbnail((500, 500))  # Skaliere das Bild
        editor_image = ImageTk.PhotoImage(img)
        editor_image_label.config(image=editor_image)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to rotate image right: {e}")

# Funktion zum Drehen des Bildes um 180°
def rotate_180():
    global editor_image
    try:
        img = Image.open(image_path)
        img = img.rotate(180, expand=True)  # Drehen um 180 Grad
        img.thumbnail((500, 500))  # Skaliere das Bild
        editor_image = ImageTk.PhotoImage(img)
        editor_image_label.config(image=editor_image)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to rotate image by 180°: {e}")

# Buttons für den Editor
frame_editor_buttons = ttk.Frame(tab_editor)
frame_editor_buttons.pack(pady=10)

button_open_editor = ttk.Button(frame_editor_buttons, text="Open in Editor", command=open_in_editor)
button_open_editor.grid(row=0, column=0, padx=5)

button_rotate_left = ttk.Button(frame_editor_buttons, text="Rotate Left", command=rotate_left)
button_rotate_left.grid(row=0, column=1, padx=5)

button_rotate_right = ttk.Button(frame_editor_buttons, text="Rotate Right", command=rotate_right)
button_rotate_right.grid(row=0, column=2, padx=5)

button_rotate_180 = ttk.Button(frame_editor_buttons, text="Rotate 180°", command=rotate_180)
button_rotate_180.grid(row=0, column=3, padx=5)


# Neue Registerkarte: Dateitext anzeigen
tab_file_text = tk.Frame(notebook, bg="white")
notebook.add(tab_file_text, text="File Text")

# Textwidget für den Dateiinhalt
file_text = tk.Text(tab_file_text, wrap="none", font=("Courier", 10), bg="white", fg="black")
file_text_scrollbar_x = ttk.Scrollbar(tab_file_text, orient="horizontal", command=file_text.xview)
file_text_scrollbar_y = ttk.Scrollbar(tab_file_text, orient="vertical", command=file_text.yview)
file_text.config(xscrollcommand=file_text_scrollbar_x.set, yscrollcommand=file_text_scrollbar_y.set)
file_text.pack(side="top", fill="both", expand=True)
file_text_scrollbar_x.pack(side="bottom", fill="x")
file_text_scrollbar_y.pack(side="right", fill="y")

# Funktion zum Anzeigen des Dateiinhalts
def display_file_text():
    try:
        with open(image_path, "rb") as f:
            content = f.read()
            try:
                decoded_content = content.decode(errors="ignore")  # Versuche, den Inhalt als Text zu dekodieren
            except Exception:
                decoded_content = str(content)  # Fallback: Zeige Rohbytes als String
            file_text.delete("1.0", "end")
            file_text.insert("1.0", decoded_content)
    except Exception as e:
        file_text.delete("1.0", "end")
        file_text.insert("1.0", f"Error displaying file text: {e}")

## Tab 4: EXIF Information
#tab_exif = tk.Frame(notebook, bg="white")
#notebook.add(tab_exif, text="EXIF Information")





# Hexdump Tab erstellen
tab_hexdump = tk.Frame(notebook, bg="white")
notebook.add(tab_hexdump, text="Hexdump")

# Textwidget für den Hexdump
hexdump_text = tk.Text(tab_hexdump, wrap="none", font=("Courier", 10), bg="white", fg="black")
hexdump_scrollbar_x = ttk.Scrollbar(tab_hexdump, orient="horizontal", command=hexdump_text.xview)
hexdump_scrollbar_y = ttk.Scrollbar(tab_hexdump, orient="vertical", command=hexdump_text.yview)
hexdump_text.config(xscrollcommand=hexdump_scrollbar_x.set, yscrollcommand=hexdump_scrollbar_y.set)
hexdump_text.pack(side="top", fill="both", expand=True)
hexdump_scrollbar_x.pack(side="bottom", fill="x")
hexdump_scrollbar_y.pack(side="right", fill="y")

# Datei Pfad (global, sollte in einer echten Anwendung durch eine Datei-Auswahl ersetzt werden)
image_path = None

def display_hexdump():
    try:
        if not image_path:
            hexdump_text.delete("1.0", "end")
            hexdump_text.insert("1.0", "No file uploaded.")
            return

        with open(image_path, "rb") as f:
            content = f.read()
            
        hex_lines = []
        for i in range(0, len(content), 16):
            chunk = content[i:i+16]
            hex_part = ' '.join(f'{byte:02X}' for byte in chunk)
            ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            hex_lines.append(f'{i:08X}  {hex_part:<47}  {ascii_part}')
        
        formatted_hex_dump = "\n".join(hex_lines)
        hexdump_text.delete("1.0", "end")
        hexdump_text.insert("1.0", formatted_hex_dump)
    except Exception as e:
        hexdump_text.delete("1.0", "end")
        hexdump_text.insert("1.0", f"Error displaying hexdump: {e}")

def search_hexdump():
    search_term = search_entry.get()
    if not search_term:
        return
    
    hexdump_text.tag_remove("highlight", "1.0", "end")
    start_pos = "1.0"
    while True:
        start_pos = hexdump_text.search(search_term, start_pos, stopindex="end", nocase=True)
        if not start_pos:
            break
        end_pos = f"{start_pos}+{len(search_term)}c"
        hexdump_text.tag_add("highlight", start_pos, end_pos)
        start_pos = end_pos
    
    hexdump_text.tag_config("highlight", background="yellow", foreground="black")

# Suchfeld und Button hinzufügen
search_frame = tk.Frame(tab_hexdump, bg="white")
search_frame.pack(side="top", fill="x")
search_entry = tk.Entry(search_frame, font=("Courier", 10))
search_entry.pack(side="left", padx=5, pady=5, expand=True, fill="x")
search_button = tk.Button(search_frame, text="Search", command=search_hexdump)
search_button.pack(side="right", padx=5, pady=5)


# Neue Registerkarte: EXIF Information
tab_exif = tk.Frame(notebook, bg="white")
notebook.add(tab_exif, text="EXIF Information")

# Treeview-Widget für die EXIF-Daten
exif_tree = ttk.Treeview(tab_exif, columns=("Key", "Value"), show="headings")
exif_tree.heading("Key", text="Key")
exif_tree.heading("Value", text="Value")
exif_tree.column("Key", width=200)
exif_tree.column("Value", width=800)
exif_tree.pack(fill="both", expand=True)

# Funktion zur Anzeige der EXIF-Informationen
def display_exif_info():
    try:
        if not image_path:
            exif_tree.delete(*exif_tree.get_children())
            exif_tree.insert("", "end", values=("Error", "No file uploaded."))
            return

        with exiftool.ExifToolHelper() as et:
            metadata = et.get_metadata(image_path)
            exif_tree.delete(*exif_tree.get_children())  # Lösche alte Einträge
            if metadata:
                for data in metadata:
                    for key, value in data.items():
                        exif_tree.insert("", "end", values=(key, value))
            else:
                exif_tree.insert("", "end", values=("Info", "No EXIF data found."))
    except Exception as e:
        exif_tree.delete(*exif_tree.get_children())
        exif_tree.insert("", "end", values=("Error", f"Error displaying EXIF information: {e}"))
 
 # Neue Registerkarte: GIMP XCF Analysis
tab_gimp_xcf = tk.Frame(notebook, bg="white")
notebook.add(tab_gimp_xcf, text="GIMP XCF Analysis")

# Treeview-Widget für die Analyseergebnisse
gimp_tree = ttk.Treeview(tab_gimp_xcf, columns=("Key", "Value"), show="headings")
gimp_tree.heading("Key", text="Key")
gimp_tree.heading("Value", text="Value")
gimp_tree.column("Key", width=200)
gimp_tree.column("Value", width=800)
gimp_tree.pack(fill="both", expand=True)

# Funktion zur Anzeige der GIMP XCF-Analyse
def display_gimp_xcf_analysis():
    try:
        if not image_path:
            gimp_tree.delete(*gimp_tree.get_children())
            gimp_tree.insert("", "end", values=("Error", "No file uploaded."))
            return

        # Überprüfe, ob die Datei ein GIMP XCF-Datei ist
        with open(image_path, "rb") as f:
            header = f.read(10)
            if not header.startswith(b"gimp"):
                gimp_tree.delete(*gimp_tree.get_children())
                gimp_tree.insert("", "end", values=("Error", "Not a valid GIMP XCF file."))
                return

        # Analysiere die GIMP XCF-Datei
        results = analyze_gimp_xcf(image_path)
        gimp_tree.delete(*gimp_tree.get_children())  # Lösche alte Einträge
        for key, value in results.items():
            gimp_tree.insert("", "end", values=(key, value))

    except Exception as e:
        gimp_tree.delete(*gimp_tree.get_children())
        gimp_tree.insert("", "end", values=("Error", f"Error analyzing GIMP XCF file: {e}"))
        
        # Funktion zur Analyse von GIMP XCF-Dateien
def analyze_gimp_xcf(path):
    """
    Analysiert eine GIMP XCF-Datei und gibt relevante Informationen zurück.
    :param path: Pfad zur GIMP XCF-Datei.
    :return: Ein Dictionary mit den Analyseergebnissen.
    """
    results = {}

    try:
        # Öffne das Bild
        img = Image.open(path)

        # 1. Layer analysieren
        layers = []
        for frame in ImageSequence.Iterator(img):  # Iteriere durch alle Layer
            layers.append(frame)
        results["Layers"] = f"{len(layers)} layers detected."

        # 2. Alphakanal und Transparenz überprüfen
        transparency = check_transparency(img)
        if transparency:
            results["Transparency"] = transparency

        # 3. Rohdaten scannen
        raw_data_results = scan_raw_data(path)
        if raw_data_results:
            results["Raw Data Findings"] = raw_data_results

        # 4. Metadaten auslesen
        metadata_results = check_metadata(path)
        if metadata_results:
            results["Metadata Findings"] = metadata_results

        # 5. Textextraktion mit OCR
        ocr_results = check_ocr(path)
        if ocr_results:
            results["OCR Text"] = ocr_results

        # 6. Farbkanal-Separierung
        color_channel_results = check_color_channels(path)
        if color_channel_results:
            results["Color Channels"] = color_channel_results

        # 7. Histogramm-Analyse
        histogram_results = check_histogram(path)
        if histogram_results:
            results["Histogram"] = histogram_results

        # 8. Pixel-Muster-Suche
        pixel_pattern_results = check_pixel_patterns(path)
        if pixel_pattern_results:
            results["Pixel Patterns"] = pixel_pattern_results

        # 9. Dateiintegrität-Überprüfung
        integrity_results = check_file_integrity(path)
        if integrity_results:
            results["File Integrity"] = integrity_results

    except Exception as e:
        results["Error"] = f"Error during analysis: {e}"

    return results
# Funktion zum Anwenden von Custom-Patterns
def apply_patterns(start_pattern, end_pattern):
    global FLAG_START, FLAG_END
    FLAG_START = start_pattern
    FLAG_END = end_pattern
    messagebox.showinfo("Patterns Updated", f"Start Pattern: {start_pattern}\nEnd Pattern: {end_pattern}")

# GUI starten
root.mainloop()
