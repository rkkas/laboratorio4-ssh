#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
raiz=$PWD
umask 077
local_dir="$raiz/.local"
nombre=udp-lab4-ssh
imagen=udp-lab4-ssh:local
puerto=2222
marca="udp-lab4=$raiz"
docker_cmd=(docker)
if [[ ${LAB4_DOCKER_SUDO:-0} == 1 ]]; then docker_cmd=(sudo docker); fi

error() { printf 'Error: %s\n' "$*" >&2; exit 1; }
necesita() { command -v "$1" >/dev/null || error "Falta $1; revisa el README."; }
docker_lab() { "${docker_cmd[@]}" "$@"; }

levantar() {
    necesita docker
    necesita ssh-keygen
    necesita ssh
    docker_lab info >/dev/null 2>&1 || error 'Docker no responde. Comprueba el servicio y tus permisos; si corresponde, usa LAB4_DOCKER_SUDO=1.'
    mkdir -p "$local_dir"
    if [[ ! -f "$local_dir/cliente" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C udp-lab4 -f "$local_dir/cliente"
    fi
    ssh-keygen -y -f "$local_dir/cliente" > "$local_dir/authorized_keys"
    chmod 0644 "$local_dir/authorized_keys"
    if docker_lab container inspect "$nombre" >/dev/null 2>&1; then
        error "Ya existe $nombre. Usa «conectar» si está activo, o «limpiar» antes de recrearlo."
    fi
    docker_lab build -t "$imagen" "$raiz/ssh"
    docker_lab run -d --name "$nombre" --label "$marca" \
        --publish "127.0.0.1:$puerto:22" \
        --mount "type=bind,source=$local_dir/authorized_keys,target=/etc/ssh/lab/authorized_keys,readonly" "$imagen"
    for _ in {1..30}; do
        if host_pub=$(docker_lab exec "$nombre" cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null) &&
            [[ $host_pub == ssh-ed25519\ * ]] &&
            docker_lab logs "$nombre" 2>&1 | awk '/Server listening/{ok=1} END{exit !ok}'; then
            printf '[127.0.0.1]:%s %s\n' "$puerto" "$host_pub" > "$local_dir/known_hosts"
            docker_lab exec "$nombre" /usr/sbin/sshd -T |
                awk '$1 ~ /^(kexalgorithms|ciphers|macs|hostkeyalgorithms|passwordauthentication|authenticationmethods)$/ {print}' \
                > "$local_dir/sshd-efectivo.txt"
            printf 'Servidor listo en 127.0.0.1:%s. Inicia la captura antes de conectar.\n' "$puerto"
            return
        fi
        sleep 1
    done
    docker_lab logs "$nombre" >&2
    error 'El servidor no inició a tiempo; revisa los mensajes anteriores.'
}

conectar() {
    necesita ssh
    [[ -s "$local_dir/known_hosts" ]] || error 'Ejecuta primero «levantar».'
    ssh -F /dev/null -vv -p "$puerto" -i "$local_dir/cliente" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$local_dir/known_hosts" -o GlobalKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o UpdateHostKeys=no \
        laboratorio@127.0.0.1 'printf "LAB4_SSH_OK\n"; id -un' \
        > "$local_dir/cliente-salida.txt" 2> "$local_dir/cliente-ssh.txt" ||
        error 'Falló SSH; revisa .local/cliente-ssh.txt.'
    cat "$local_dir/cliente-salida.txt"
    awk '/kex: algorithm:|kex: host key algorithm:|kex: server->client cipher:|kex: client->server cipher:|Authenticated to/{print}' \
        "$local_dir/cliente-ssh.txt" | tee "$local_dir/negociacion.txt"
}

analizar() {
    necesita tshark
    local captura=${1:-"$local_dir/ssh-lab4.pcapng"}
    [[ -r "$captura" ]] || error "No se pudo leer $captura"
    mkdir -p "$local_dir"
    local temp
    temp=$(mktemp "$local_dir/trafico-ssh.XXXXXX")
    if tshark -r "$captura" -d "tcp.port==$puerto,ssh" -Y "tcp.port==$puerto && ssh" \
        -T fields -E header=y -e frame.number -e ip.src -e tcp.srcport \
        -e ip.dst -e tcp.dstport -e ssh.protocol -e ssh.message_code -e _ws.col.Info > "$temp" &&
        [[ $(wc -l < "$temp") -gt 1 ]]; then
        mv -- "$temp" "$local_dir/trafico-ssh.tsv"
        cat "$local_dir/trafico-ssh.tsv"
    else
        rm -f -- "$temp"
        error 'No se observó SSH en el puerto 2222 de esta captura.'
    fi
}

capturar() {
    necesita tcpdump
    necesita sudo
    necesita tshark
    [[ -s "$local_dir/known_hosts" ]] || error 'Ejecuta primero «levantar».'
    [[ ! -e "$local_dir/ssh-lab4.pcap" ]] || error 'Ya existe .local/ssh-lab4.pcap; renómbralo antes de capturar otra vez.'
    sudo -v
    # Captura solo la conexión de prueba en la interfaz de loopback.
    LC_ALL=C timeout --signal=INT 14s sudo -n tcpdump -U -s 0 -i lo -w - \
        'host 127.0.0.1 and tcp port 2222' > "$local_dir/ssh-lab4.pcap" \
        2> "$local_dir/captura.log" &
    local cap=$! inicio=0 estado=0
    for _ in {1..40}; do
        if grep -q 'listening on' "$local_dir/captura.log"; then inicio=1; break; fi
        kill -0 "$cap" 2>/dev/null || break
        sleep .1
    done
    if (( ! inicio )); then
        wait "$cap" || true
        cat "$local_dir/captura.log" >&2
        error 'No se pudo iniciar la captura automática. Usa Wireshark con la guía.'
    fi
    conectar
    wait "$cap" || estado=$?
    [[ $estado == 0 || $estado == 124 ]] || error 'tcpdump terminó con error; revisa .local/captura.log.'
    analizar "$local_dir/ssh-lab4.pcap"
}

descifrar() {
    local py=python3
    [[ ! -x "$raiz/.venv/bin/python" ]] || py="$raiz/.venv/bin/python"
    necesita "$py"
    for archivo in transacciones_cifradas.pcap clave_privada.pem clave_publica.pem; do
        [[ -r "datos/$archivo" ]] || error "Falta datos/$archivo. Revisa datos/LEEME.md."
    done
    "$py" -c 'import cryptography' >/dev/null 2>&1 ||
        error 'Instala python3-cryptography o la dependencia en .venv (ver README).'
    "$py" scripts/descifrar.py datos/transacciones_cifradas.pcap datos/clave_privada.pem \
        datos/clave_publica.pem --salida "$local_dir/descifrado"
}

limpiar() {
    necesita docker
    [[ $(docker_lab inspect -f '{{index .Config.Labels "udp-lab4"}}' "$nombre") == "$raiz" ]] ||
        error "No hay un contenedor de este proyecto para borrar."
    docker_lab rm -f "$nombre"
    printf 'Contenedor eliminado. Los archivos quedan en .local.\n'
}

case ${1:-ayuda} in
    revisar)
        for c in docker ssh ssh-keygen wireshark tshark tcpdump python3 latexmk; do
            if command -v "$c" >/dev/null; then printf 'Disponible: %s\n' "$c"
            else printf 'No encontrado: %s\n' "$c"; fi
        done ;;
    levantar) levantar ;;
    conectar) conectar ;;
    analizar) analizar "${2:-}" ;;
    capturar) capturar ;;
    descifrar) descifrar ;;
    pdf) necesita latexmk; mkdir -p "$local_dir/pdf"; cd informe
        latexmk -g -pdf -interaction=nonstopmode -halt-on-error -outdir="$local_dir/pdf" informe.tex
        printf 'PDF: %s\n' "$local_dir/pdf/informe.pdf" ;;
    limpiar) limpiar ;;
    ayuda|-h|--help) printf 'Uso: bash scripts/lab4.sh {revisar|levantar|conectar|analizar [archivo]|capturar|descifrar|pdf|limpiar}\n' ;;
    *) error "Acción desconocida: $1" ;;
esac
