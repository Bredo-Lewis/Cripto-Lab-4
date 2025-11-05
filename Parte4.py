from binascii import unhexlify, hexlify
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def ajustar_longitud(data_hex, expected_length, label):
    try:
        data = unhexlify(data_hex.strip())
    except Exception:
        print(f"{label} inválido. Se generará aleatoriamente.")
        data = b''

    if len(data) < expected_length:
        faltantes = expected_length - len(data)
        extra = get_random_bytes(faltantes)
        data += extra
        print(f"{label} era más corto. Se agregaron {faltantes} bytes aleatorios.")
    elif len(data) > expected_length:
        data = data[:expected_length]
        print(f"{label} era más largo. Se truncó a {expected_length} bytes.")

    return data

def cifrar_descifrar_des(key, iv, texto):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pad(texto.encode(), DES.block_size)
    cifrado = cipher.encrypt(padded)

    decipher = DES.new(key, DES.MODE_CBC, iv)
    descifrado = unpad(decipher.decrypt(cifrado), DES.block_size)
    return cifrado, descifrado


def cifrar_descifrar_3des(key, iv, texto):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(texto.encode(), DES3.block_size)
    cifrado = cipher.encrypt(padded)

    decipher = DES3.new(key, DES3.MODE_CBC, iv)
    descifrado = unpad(decipher.decrypt(cifrado), DES3.block_size)
    return cifrado, descifrado


def cifrar_descifrar_aes256(key, iv, texto):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(texto.encode(), AES.block_size)
    cifrado = cipher.encrypt(padded)

    decipher = AES.new(key, AES.MODE_CBC, iv)
    descifrado = unpad(decipher.decrypt(cifrado), AES.block_size)
    return cifrado, descifrado

def main():
    print("Ingreso de datos para cifrado")
    print("Algoritmos: DES, 3DES, AES-256")

    algoritmo = input("Ingresa el algoritmo: ").strip().upper()

    if algoritmo == "DES":
        key_len, iv_len = 8, 8
    elif algoritmo == "3DES":
        key_len, iv_len = 24, 8
    elif algoritmo == "AES-256":
        key_len, iv_len = 32, 16
    else:
        print("Algoritmo no válido. Debe ser DES, 3DES o AES-256.")
        return

    key_hex = input(f"Ingresa la clave ({key_len} bytes = {key_len*2} hex): ").strip()
    iv_hex = input(f"Ingresa el IV ({iv_len} bytes = {iv_len*2} hex): ").strip()
    key = ajustar_longitud(key_hex, key_len, "Clave")
    iv = ajustar_longitud(iv_hex, iv_len, "IV")

    texto = input("Ingresa el texto a cifrar: ").strip()

    if algoritmo == "DES":
        cifrado, descifrado = cifrar_descifrar_des(key, iv, texto)
    elif algoritmo == "3DES":
        cifrado, descifrado = cifrar_descifrar_3des(key, iv, texto)
    else:
        cifrado, descifrado = cifrar_descifrar_aes256(key, iv, texto)

    print("\nDatos finales")
    print(f"Algoritmo: {algoritmo}")
    print(f"Clave final ({len(key)} bytes): {hexlify(key).decode()}")
    print(f"IV final ({len(iv)} bytes): {hexlify(iv).decode()}")
    print(f"Texto original: {texto}")
    print(f"Texto cifrado (hex): {hexlify(cifrado).decode()}")
    print(f"Texto descifrado: {descifrado.decode()}")


if __name__ == "__main__":
    main()
