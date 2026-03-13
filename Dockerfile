# syntax=docker/dockerfile:1

# stages:
# - release: builds release binary
# - export: minimal binary export
# - runtime: prepares the release image
#
# We first set default values for build arguments used across the stages.
# Each stage must define the build arguments (ARGs) it uses.
ARG FEATURES=""

ARG UID=10801
ARG GID=${UID}
ARG USER="user"
ARG HOME="/home/${USER}"
ARG CARGO_HOME="/usr/local/cargo"
ARG CARGO_TARGET_DIR="${HOME}/target"
ARG TARGET_ARCH="x86_64-unknown-linux-musl"

FROM stagex/core-busybox:1.37.0@sha256:d608daa946e4799cf28b105aba461db00187657bd55ea7c2935ff11dac237e27 AS busybox
FROM stagex/pallet-rust:1.94.0@sha256:2fbe7b164dd92edb9c1096152f6d27592d8a69b1b8eb2fc907b5fadea7d11668 AS pallet-rust

# This stage builds the zcash-devtool release binary.
FROM pallet-rust AS release

SHELL ["/bin/sh", "-xo", "pipefail", "-c"]

ARG HOME
WORKDIR ${HOME}

ARG CARGO_INCREMENTAL
# default to 0, disables incremental compilation.
ENV CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}

ARG CARGO_HOME
ENV CARGO_HOME=${CARGO_HOME}

ARG CARGO_TARGET_DIR
ARG TARGET_ARCH
ARG FEATURES

ENV RUST_BACKTRACE=1
ENV RUSTFLAGS="-C codegen-units=1"
ENV RUSTFLAGS="${RUSTFLAGS} -C target-feature=+crt-static"
ENV RUSTFLAGS="${RUSTFLAGS} -C link-arg=-Wl,--build-id=none"

ENV SOURCE_DATE_EPOCH=1
ENV CXXFLAGS="-include cstdint"

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src/ src/

RUN --mount=type=cache,target=/usr/local/cargo/registry/ \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=${CARGO_HOME} \
    cargo fetch --locked --target $TARGET_ARCH
    
RUN --network=none \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=${CARGO_TARGET_DIR} \
    --mount=type=cache,target=${CARGO_HOME} \
    cargo build --frozen --release ${FEATURES:+--features ${FEATURES}} --target ${TARGET_ARCH} && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/zcash-devtool /usr/local/bin/zcash-devtool

# This stage is used to export the binary
FROM scratch AS export
COPY --from=release /usr/local/bin/* /

# This stage starts from StageX/busybox and copies the built
# zcash-devtool binary from the `release` stage
FROM busybox AS runtime

ARG FEATURES
ENV FEATURES=${FEATURES}

# Create a non-privileged user for running `zcash-devtool`.
#
# We use a high UID/GID (10801) to avoid overlap with host system users.
# This reduces the risk of container user namespace conflicts with host accounts,
# which could potentially lead to privilege escalation if a container escape occurs.
#
# We do not use the `--system` flag for user creation since:
# 1. System user ranges (100-999) can collide with host system users
#   (see: https://github.com/nginxinc/docker-nginx/issues/490)
# 2. There's no value added and warning messages can be raised at build time
#   (see: https://github.com/dotnet/dotnet-docker/issues/4624)
#
# The high UID/GID values provide an additional security boundary in containers
# where user namespaces are shared with the host.
ARG UID
ENV UID=${UID}
ARG GID
ENV GID=${GID}
ARG USER
ENV USER=${USER}
ARG HOME
ENV HOME=${HOME}

COPY --chmod=550 <<-EOF /etc/passwd
	root:x:0:0:root:/root:/bin/sh
	user:x:${UID}:${GID}::${HOME}:/bin/sh
EOF

COPY --chmod=550 <<-EOF /etc/group
	root:x:0:
	user:x:${GID}:
EOF

COPY --from=release /usr/local/bin/zcash-devtool /usr/local/bin/
COPY ./utils/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN mkdir -p /usr/local/bin/zec_sqlite_wallet && chown -R ${UID}:${GID} /usr/local/bin/ && chmod -R 770 /usr/local/bin/ && chmod 550 /usr/local/bin/zcash-devtool
WORKDIR /usr/local/bin
USER ${UID}:${GID}

ENTRYPOINT [ "entrypoint.sh" ]
CMD [ "./zcash-devtool" ]
