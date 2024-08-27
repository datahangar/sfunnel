FROM debian:bookworm-slim

#sfunnel VERSION
ARG VERSION="unknown"
ARG COMMIT="unknown"

WORKDIR /

#First install deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    clang \
    libbpf-dev \
    iproute2 \
    python3 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

#Copy sfunnel stuff
COPY tools/ /opt/sfunnel/tools/
COPY src/ /opt/sfunnel/src/
COPY ./docker/entrypoint.sh /opt/sfunnel
RUN chmod +x /opt/sfunnel/entrypoint.sh && \
  ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
  cd /opt/sfunnel/src/ && make && echo "${VERSION}(${COMMIT})" > /opt/sfunnel/VERSION

#Cleanup image
RUN apt-get clean && rm -rf /var/lib/apt/lists/* && \
  rm -rf /var/tmp/* && rm -rf /tmp/* && rm -rf /usr/share/doc/* && \
  rm -rf /usr/share/doc/* && rm -rf /usr/share/man/* && rm -rf /usr/share/info/* && \
  find /usr/share/locale -mindepth 1 -maxdepth 1 ! -name 'en*' -exec rm -rf {} +

ENTRYPOINT ["/opt/sfunnel/entrypoint.sh"]
