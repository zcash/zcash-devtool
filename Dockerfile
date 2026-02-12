# syntax=docker/dockerfile:1

# stages:
# - setup: sets default values
# - release: builds release binaries
# - runtime: prepares the release image
#
# We first set default values for build arguments used across the stages.
# Each stage must define the build arguments (ARGs) it uses.

ARG RUST_VERSION=1.91.1

ARG FEATURES=""

ARG UID=10801
ARG GID=${UID}
ARG USER="devtool-user"
ARG HOME="/home/${USER}"
ARG CARGO_HOME="${HOME}/.cargo"
ARG CARGO_TARGET_DIR="${HOME}/target"
ARG TARGET_ARCH="x86_64-unknown-linux-musl"

FROM stagex/core-busybox@sha256:d608daa946e4799cf28b105aba461db00187657bd55ea7c2935ff11dac237e27 AS busybox
FROM stagex/pallet-rust@sha256:4062550919db682ebaeea07661551b5b89b3921e3f3a2b0bc665ddea7f6af1ca AS pallet-rust

# This stage captures build args as env vars
FROM pallet-rust AS setup

SHELL ["/bin/sh", "-xo", "pipefail", "-c"]

# Build arguments and variables
ARG CARGO_INCREMENTAL
# default to 0, disables incremental compilation.
ENV CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}

ARG CARGO_HOME
ENV CARGO_HOME=${CARGO_HOME}

ARG FEATURES
ENV FEATURES=${FEATURES}

# This stage builds the zcash-devtool release binary.
FROM setup AS release

ARG HOME
WORKDIR ${HOME}

ARG CARGO_HOME
ARG CARGO_TARGET_DIR
ARG TARGET_ARCH

ENV RUST_BACKTRACE=1
ENV RUSTFLAGS="-C codegen-units=1"
ENV RUSTFLAGS="${RUSTFLAGS} -C target-feature=+crt-static"
ENV RUSTFLAGS="${RUSTFLAGS} -C link-arg=-Wl,--build-id=none"

ENV SOURCE_DATE_EPOCH=1
ENV CXXFLAGS="-include cstdint"
# ENV ROCKSDB_USE_PKG_CONFIG=0

# --mount=type=bind instead?
# --mount=type=bind,source=src,target=/app/src \
COPY . .

RUN --mount=type=bind,source=Cargo.toml,target=Cargo.toml,ro \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock,ro \
		--mount=type=cache,target=${HOME}/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    --mount=type=cache,target=${CARGO_TARGET_DIR} \
    --mount=type=cache,target=${CARGO_HOME} \
    cargo fetch --locked --target $TARGET_ARCH && \
    cargo metadata --locked --format-version=1 > /dev/null 2>&1
    
RUN --network=none \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml,ro \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock,ro \
    --mount=type=cache,target=${HOME}/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    --mount=type=cache,target=${CARGO_TARGET_DIR} \
    --mount=type=cache,target=${CARGO_HOME} \
    cargo build --frozen --release --features "${FEATURES}" --target ${TARGET_ARCH} && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/zcash-devtool /usr/local/bin/zcash-devtool

# This stage is used for exporting the binaries
FROM scratch AS export
COPY --from=release /usr/local/bin/* /

# This stage starts from scratch using StageX and copies the built
# zcash-devtool binary from the `release` stage
FROM scratch AS runtime
COPY --from=setup /usr/bin/busybox . /
RUN ["busybox", "--install", "-s", "usr/bin"]

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


COPY --chmod=644 <<-EOF /etc/passwd
	root:x:0:0:root:/root:/bin/sh
	user:x:${UID}:${GID}::${HOME}:/bin/sh
EOF

COPY --chmod=644 <<-EOF /etc/group
	root:x:0:
	user:x:${GID}:
EOF

USER ${UID}:${GID}

WORKDIR ${HOME}

# We're explicitly NOT using the USER directive here.
# Instead, we run as root initially and use setpriv in the entrypoint.sh
# to step down to the non-privileged user. This allows us to change permissions
# on mounted volumes before running the application as a non-root user.
# User with UID=${UID} is created above and used via setpriv in entrypoint.sh.

COPY --from=release /usr/local/bin/zcash-devtool /usr/local/bin/
# COPY --chown=${UID}:${GID} ./docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
CMD ["zcash-devtool"]
