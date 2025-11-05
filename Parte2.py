from binascii import unhexlify

def get_bytes_input(prompt, expected_length):
    while True:
        data_hex = input(prompt).strip()
        try:
            data = unhexlify(data_hex)
            if len(data) != expected_length:
                print(f"Longitud incorrecta. Se esperaban {expected_length} bytes ({expected_length*8} bits).")
                continue
            return data
        except Exception:
            print("Input Erróneo. Debe ingresar una cadena en formato hexadecimal.")


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

    key = get_bytes_input(f"Ingresa la clave ({key_len} bytes = {key_len*2} hex): ", key_len)
    iv = get_bytes_input(f"Ingresa el IV ({iv_len} bytes = {iv_len*2} hex): ", iv_len)

    texto = input("Ingresa el texto a cifrar: ").strip()

if __name__ == "__main__":
    main()
