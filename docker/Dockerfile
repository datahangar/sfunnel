FROM debian:bookworm-slim

WORKDIR /

#deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    gcc \
    make \
    libc6-dev \
    linux-headers-amd64 \
    linux-libc-dev \
    git \
    libelf-dev \
    libbpf-dev \
    iproute2 \
    python3 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

#First install deps
COPY tools/ /opt/sfunnel/tools/
COPY src/ /opt/sfunnel/src/
COPY ./docker/entrypoint.sh /opt/sfunnel
RUN chmod +x /opt/sfunnel/entrypoint.sh && \
	ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
	cd /opt/sfunnel/src/ && make
RUN mv /opt/sfunnel/src/tc_sfunnel.o /opt/sfunnel
ENTRYPOINT ["/opt/sfunnel/entrypoint.sh"]
