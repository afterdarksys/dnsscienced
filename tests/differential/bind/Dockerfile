FROM debian:bookworm-slim

ARG BIND_VERSION=9.20.24
ARG BIND_SHA256=989fef1fc88ea59d04cd86f854dca5a4616a20a9968bcdde3c1a3668ab36be08

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl libcap-dev libjson-c-dev \
        libnghttp2-dev libssl-dev liburcu-dev libuv1-dev libxml2-dev \
        pkg-config xz-utils \
    && curl -fsSLo /tmp/bind.tar.xz \
        "https://downloads.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz" \
    && echo "${BIND_SHA256}  /tmp/bind.tar.xz" | sha256sum -c - \
    && mkdir /tmp/bind \
    && tar -xJf /tmp/bind.tar.xz -C /tmp/bind --strip-components=1 \
    && cd /tmp/bind \
    && ./configure \
        --prefix=/opt/bind \
        --sysconfdir=/etc/bind \
        --localstatedir=/var \
        --disable-doh \
        --disable-dnstap \
        --disable-geoip \
        --without-lmdb \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/bind /tmp/bind.tar.xz /var/lib/apt/lists/*

RUN mkdir -p /var/cache/bind /zones

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/opt/bind/sbin/named"]
CMD ["-g", "-c", "/etc/bind/named.conf"]
