FROM debian:bookworm-slim

ARG NSD_VERSION=4.15.0
ARG NSD_SHA256=84f1bee2e92a9dadb41d95ecc64113e4d3def86224de774cd92003add8c4f570

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison build-essential ca-certificates curl flex libevent-dev libssl-dev \
    && curl -fsSLo /tmp/nsd.tar.gz \
        "https://www.nlnetlabs.nl/downloads/nsd/nsd-${NSD_VERSION}.tar.gz" \
    && echo "${NSD_SHA256}  /tmp/nsd.tar.gz" | sha256sum -c - \
    && mkdir /tmp/nsd \
    && tar -xzf /tmp/nsd.tar.gz -C /tmp/nsd --strip-components=1 \
    && cd /tmp/nsd \
    && ./configure \
        --prefix=/opt/nsd \
        --sysconfdir=/etc/nsd \
        --disable-dnstap \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/nsd /tmp/nsd.tar.gz /var/lib/apt/lists/*

RUN mkdir -p /etc/nsd /zones /var/db/nsd /var/log/nsd /var/run

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/opt/nsd/sbin/nsd"]
CMD ["-d", "-c", "/etc/nsd/nsd.conf"]
