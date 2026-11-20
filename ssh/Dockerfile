FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --create-home --shell /bin/sh laboratorio \
    && usermod --password 'NP' laboratorio \
    && mkdir -p /run/sshd /etc/ssh/lab
COPY sshd_config /etc/ssh/sshd_config
COPY iniciar.sh /usr/local/bin/lab4-iniciar
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/usr/local/bin/lab4-iniciar"]
