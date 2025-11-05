from binascii import unhexlify, hexlify
from Crypto.Random import get_random_bytes

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

    print("\nDatos finales")
    print(f"Algoritmo: {algoritmo}")
    print(f"Clave final ({len(key)} bytes): {hexlify(key).decode()}")
    print(f"IV final ({len(iv)} bytes): {hexlify(iv).decode()}")
    print(f"Texto: {texto}")


if __name__ == "__main__":
    main()
