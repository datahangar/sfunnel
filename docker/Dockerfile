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
    && apt-get clean && rm -rf /var/lib/apt/lists/*

#First install deps
COPY ./src /opt/sfunnel
COPY ./docker/entrypoint.sh /opt/sfunnel
RUN chmod +x /opt/sfunnel/entrypoint.sh && \
	ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
	cd /opt/sfunnel/ && make

ENTRYPOINT ["/opt/sfunnel/entrypoint.sh"]
CMD ["unfunnel"]
