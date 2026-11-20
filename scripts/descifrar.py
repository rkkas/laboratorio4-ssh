#!/usr/bin/env python3
"""Lee la captura oficial del curso (PCAP sobre IPv4/TCP) y usa sus claves RSA."""
import argparse
import hashlib
import ipaddress
import os
import re
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_TAG = b"RSA_PIN|"
AES_TAG = b"AESGCM|"


def leer_captura(ruta):
    endian = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }
    with ruta.open("rb") as archivo:
        cab = archivo.read(24)
        if len(cab) != 24 or cab[:4] not in endian:
            raise ValueError("Se requiere un PCAP clásico, no PCAPNG.")
        orden = endian[cab[:4]]
        _, _, _, _, limite, enlace = struct.unpack(orden + "HHIIII", cab[4:])
        if enlace not in (101, 228):
            raise ValueError(f"Tipo de enlace {enlace}: se esperaba IPv4 sin Ethernet.")
        trama = 0
        while cab := archivo.read(16):
            trama += 1
            if len(cab) != 16:
                raise ValueError(f"Cabecera incompleta en trama {trama}.")
            _, _, capturado, original = struct.unpack(orden + "IIII", cab)
            if capturado > limite or capturado > original or capturado > 1024 * 1024:
                raise ValueError(f"Longitud inválida en trama {trama}.")
            paquete = archivo.read(capturado)
            if len(paquete) != capturado or capturado != original:
                raise ValueError(f"Trama {trama} truncada.")
            yield trama, paquete


def carga_tcp(paquete):
    if len(paquete) < 20 or paquete[0] >> 4 != 4 or paquete[9] != 6:
        return None
    ip_h = (paquete[0] & 15) * 4
    total = int.from_bytes(paquete[2:4], "big")
    if ip_h < 20 or total > len(paquete) or total < ip_h + 20:
        raise ValueError("Cabeceras IPv4/TCP inválidas.")
    if int.from_bytes(paquete[6:8], "big") & 0x3fff:
        raise ValueError("Este analizador no admite fragmentos IPv4.")
    tcp_h = (paquete[ip_h + 12] >> 4) * 4
    if tcp_h < 20 or ip_h + tcp_h > total:
        raise ValueError("Longitud de cabecera TCP inválida.")
    origen = ipaddress.IPv4Address(paquete[12:16])
    destino = ipaddress.IPv4Address(paquete[16:20])
    p_origen, p_destino, secuencia = struct.unpack_from("!HHI", paquete, ip_h)
    return (str(origen), p_origen, str(destino), p_destino), secuencia, paquete[ip_h+tcp_h:total]


def procesar(captura, privada_path, publica_path):
    privada = serialization.load_pem_private_key(privada_path.read_bytes(), password=None)
    publica = serialization.load_pem_public_key(publica_path.read_bytes())
    if not isinstance(privada, rsa.RSAPrivateKey) or not isinstance(publica, rsa.RSAPublicKey):
        raise ValueError("Se requieren las dos claves RSA suministradas para el lab.")
    if privada.public_key().public_numbers() != publica.public_numbers():
        raise ValueError("Las claves RSA no pertenecen al mismo par.")

    clave_aes = None
    tramas, mensajes, nonces = [], [], set()
    vistos = set()
    flujo_rsa = None
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    for num, paquete in leer_captura(captura):
        tcp = carga_tcp(paquete)
        if tcp is None:
            continue
        flujo, seq, carga = tcp
        if not carga.startswith((RSA_TAG, AES_TAG)):
            continue
        segmento = (flujo, seq, carga)
        if segmento in vistos:
            continue
        vistos.add(segmento)
        if carga.startswith(RSA_TAG):
            if clave_aes is not None:
                raise ValueError(f"Más de un registro RSA_PIN; segundo en trama {num}.")
            resto = carga[len(RSA_TAG):]
            if len(resto) != 16 + (privada.key_size + 7) // 8:
                raise ValueError(f"Tamaño inesperado para RSA_PIN en trama {num}.")
            sal, cifrado = resto[:16], resto[16:]
            try:
                pin = privada.decrypt(cifrado, oaep)
            except ValueError as error:
                raise ValueError(f"No se pudo abrir RSA-OAEP en trama {num}.") from error
            if re.fullmatch(rb"[0-9]{4}", pin) is None:
                raise ValueError("El PIN recuperado no coincide con cuatro dígitos ASCII.")
            clave_aes = AESGCM(hashlib.scrypt(pin, salt=sal, n=2**14, r=8, p=1, dklen=32))
            flujo_rsa = flujo
            tramas.append((num, "RSA_PIN", len(carga), "sal=16", f"RSA={len(cifrado)}"))
            continue

        if clave_aes is None or flujo != flujo_rsa:
            raise ValueError(f"Registro AESGCM sin contexto RSA válido en trama {num}.")
        resto = carga[len(AES_TAG):]
        if len(resto) <= 12 + 16:
            raise ValueError(f"AESGCM incompleto en trama {num}.")
        nonce, cifrado_tag = resto[:12], resto[12:]
        try:
            plano = clave_aes.decrypt(nonce, cifrado_tag, None)
        except InvalidTag as error:
            raise ValueError(f"Etiqueta GCM inválida en trama {num}; resultados no escritos.") from error
        nonces.add(nonce)
        mensajes.append(plano)
        tramas.append((num, "AESGCM", len(carga), "nonce=12; tag=16", "autenticado"))
    if clave_aes is None or not mensajes:
        raise ValueError("No se encontraron los dos tipos de registros esperados.")
    return privada.key_size, tramas, mensajes, len(nonces)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("captura", type=Path)
    p.add_argument("privada", type=Path)
    p.add_argument("publica", type=Path)
    p.add_argument("--salida", type=Path, required=True)
    a = p.parse_args()
    try:
        bits, tramas, mensajes, nonces = procesar(a.captura, a.privada, a.publica)
        os.umask(0o077)
        a.salida.mkdir(parents=True, exist_ok=True)
        (a.salida / "transacciones.txt").write_bytes(b"\n".join(mensajes) + b"\n")
        inventario = "".join("\t".join(map(str, fila)) + "\n" for fila in tramas)
        (a.salida / "tramas.tsv").write_text(
            "Trama\tEtiqueta\tCarga TCP (bytes)\tCampos\tResultado\n" + inventario,
            encoding="utf-8",
        )
        resumen = (
            f"RSA: {bits} bits; par de claves verificado.\n"
            f"RSA_PIN: trama {tramas[0][0]}; PIN de 4 dígitos recuperado.\n"
            "Scrypt: N=16384, r=8, p=1; sal de 16 bytes; salida de 32 bytes.\n"
            f"AESGCM: {len(mensajes)} mensajes autenticados; {nonces} nonces distintos.\n"
            f"Tramas AESGCM: {', '.join(str(f[0]) for f in tramas[1:])}.\n"
        )
        (a.salida / "verificacion.txt").write_text(resumen, encoding="utf-8")
        print(resumen, end="")
        print(f"Mensajes originales guardados en {a.salida / 'transacciones.txt'}.")
    except (OSError, ValueError, TypeError) as error:
        p.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
