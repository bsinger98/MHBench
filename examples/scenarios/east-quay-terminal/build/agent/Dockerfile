FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl dnsutils iproute2 mosquitto-clients nmap \
      netcat-openbsd openssh-client procps python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash pentest
USER pentest
WORKDIR /home/pentest
CMD ["sleep", "infinity"]
