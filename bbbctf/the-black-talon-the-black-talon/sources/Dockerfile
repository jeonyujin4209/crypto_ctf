FROM rust:slim@sha256:81099830a1e1d244607b9a7a30f3ff6ecadc52134a933b4635faba24f52840c9 AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/build/target \
    OPENSSL_NO_VENDOR=1 cargo build --release \
    && cp target/release/orchestrator target/release/network target/release/client /tmp/

FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a as chroot
RUN apt-get update && apt-get install -y socat netcat-openbsd libssl3t64 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/orchestrator /challenge/orchestrator
COPY --from=builder /tmp/network /challenge/network
COPY --from=builder /tmp/client /challenge/client

FROM ghcr.io/bbb-ctf/quals-template-jail:20e797bf2baa09ac1ab0f6894c03dbcdacac9012
COPY --from=chroot / /chroot
COPY nsjail.cfg /home/user/

ARG FLAG=bbb{test_flag}
RUN [ -n "$FLAG" ] && echo -n "$FLAG" > /flag || true
RUN touch /chroot/challenge/flag

EXPOSE 1337
CMD ["kctf_setup", "socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:kctf_nsjail_flag_at /challenge/flag -- /challenge/orchestrator"]
