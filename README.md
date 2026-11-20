# Laboratorio 4 · Criptografía y Seguridad en Redes

El laboratorio analiza una conexión SSH a un servidor OpenSSH en Docker y
descifra con RSA-OAEP y AES-GCM la captura oficial del curso. El servidor
del laboratorio escucha en `127.0.0.1:2222` en la VM de Ubuntu.

## Preparar Ubuntu

Abre una terminal en la carpeta del proyecto y comprueba las dependencias.

```bash
bash scripts/lab4.sh revisar
```

Instala los paquetes que falten. Si la VM ya tiene una instalación funcional
de Docker, omite `docker.io`.

```bash
sudo apt update
sudo apt install docker.io openssh-client wireshark tshark python3-cryptography
sudo apt install latexmk texlive-latex-extra texlive-lang-spanish lmodern
```

## Configurar y capturar SSH

1. Levanta el contenedor. El [Dockerfile](ssh/Dockerfile) instala OpenSSH y
   [sshd_config](ssh/sshd_config) configura los algoritmos de la práctica.

   ```bash
   bash scripts/lab4.sh levantar
   ```

   Si tu instalación usa `sudo` para Docker, ejecuta
   `LAB4_DOCKER_SUDO=1 bash scripts/lab4.sh levantar`.

2. Cuando el servidor esté listo, inicia Wireshark en la interfaz **lo**
   con el filtro de captura `tcp port 2222`. Con la captura activa, ejecuta el cliente SSH.

   ```bash
   bash scripts/lab4.sh conectar
   ```

   La salida esperada es `LAB4_SSH_OK` y el usuario `laboratorio`. El
   registro del cliente y los algoritmos negociados quedan en `.local/`.

3. Detén la captura y guárdala como `.local/ssh-lab4.pcapng`. Si capturaste
   tráfico adicional, aplica el filtro de visualización `tcp.port == 2222`
   y exporta los paquetes mostrados. Si hace falta asignar el protocolo,
   usa **Analizar → Decodificar como…** y elige **SSH** para el puerto 2222.

   El directorio `evidencias/` contiene las tres imágenes revisadas.

   - `ssh-version.png` muestra las versiones SSH, las IP y los puertos.
   - `ssh-kexinit.png` muestra las propuestas de algoritmos.
   - `ssh-newkeys.png` muestra el cambio de claves y el tráfico cifrado posterior.

4. Extrae las tramas SSH con TShark.

   ```bash
   bash scripts/lab4.sh analizar
   ```

Si Wireshark carece de permisos de captura, puedes usar el respaldo del
proyecto. Necesita `tcpdump` y permisos de `sudo`. El comando captura en
`lo` antes de abrir la conexión y guarda `.local/ssh-lab4.pcap`.

```bash
sudo apt install tcpdump
bash scripts/lab4.sh capturar
```

## Descifrar la captura oficial

Descarga los archivos desde [Captura y Claves del Laboratorio 4](https://drive.google.com/drive/folders/1rXMp5y9WeBR36iytc4RBaqXKWf3ea-WU).
Crea la carpeta local `datos/` en la raíz del proyecto y coloca ahí estos
tres archivos con sus nombres originales.

```text
datos/transacciones_cifradas.pcap
datos/clave_privada.pem
datos/clave_publica.pem
```

En Wireshark, el filtro de visualización `tcp.dstport == 4444 && tcp.len > 0`
muestra la trama 1 con `RSA_PIN|` y las tramas 2 a 41 con `AESGCM|`.

```bash
bash scripts/lab4.sh descifrar
```

El comando ejecuta [scripts/descifrar.py](scripts/descifrar.py) y guarda las
transacciones originales en `.local/descifrado/transacciones.txt` tras
autenticar todos los mensajes. El inventario y resumen revisados en
`evidencias/tramas.tsv` y `evidencias/verificacion.txt` documentan la
verificación de los 40 mensajes y los tamaños de los campos.

## Compilar el informe académico

```bash
bash scripts/lab4.sh pdf
```

El PDF se genera en `.local/pdf/informe.pdf` a partir de
[informe/informe.tex](informe/informe.tex). Si están disponibles, se incorporan
las imágenes, el registro SSH y las transacciones recuperadas. La entrega
académica del PDF se hace por separado. Git excluye `datos/`, `.local/`,
los archivos de claves y los PDF generados.

Para retirar el contenedor al terminar, ejecuta `bash scripts/lab4.sh limpiar`.
Si lo levantaste con `LAB4_DOCKER_SUDO=1`, usa la misma variable al retirarlo.
