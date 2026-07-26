# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Simon Wright

# Trigstation directory service.
#
# Two stages: a toolchain that produces one static binary, and a final image
# that contains that binary and as little else as will run it. See
# DIRECTORY-SPEC.md §9 — the deployment story is "set a domain, get a
# certificate, run", and every choice here serves that.


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# The floor is set by modernc.org/sqlite, which declares go 1.25.0. Raising this
# is fine; lowering it below go.mod will not build.
ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Dependencies first, so that editing source does not re-download the module
# cache on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 is the whole deployment story, not a preference. A single static
# binary that cross-compiles from one machine is what makes a directory
# genuinely replaceable (CLAUDE.md; DIRECTORY-SPEC.md §9), and modernc.org/sqlite
# is a pure-Go driver chosen precisely so this holds. If this ever needs a C
# toolchain, something has gone wrong upstream of the Dockerfile.
#
# -trimpath keeps build machine paths out of the binary; -buildvcs=false is
# needed because .dockerignore excludes .git, so there is no VCS to stamp from.
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/trigstationd .

# The database directory is created here, with its ownership and mode, because
# the final image has no shell to create it with and no mkdir to call. Docker
# copies an image directory's contents *and its ownership* into a fresh named
# volume, so /data comes out writable by the unprivileged user the container
# runs as. 65532 is distroless's `nonroot`.
#
# 0700 rather than 0755: the SQLite file holds only ciphertext the directory
# cannot read (invariant 2), but nothing else in the image has any business
# reading it either.
#
# It is staged under rootfs/ and copied as a child rather than copied directly,
# because `COPY a /b` creates /b itself at the default 0755 and applies the
# source mode only to what is inside it. Copying rootfs/ onto / makes data a
# child of the copy, so its 0700 survives. This is verified, not assumed.
RUN mkdir -p /out/rootfs/data \
    && chown -R 65532:65532 /out/rootfs \
    && chmod 0700 /out/rootfs/data


# ---------------------------------------------------------------------------
# Final image
# ---------------------------------------------------------------------------

# distroless/static rather than scratch.
#
# scratch is the smaller answer and would very nearly work: the binary is static
# and the service opens no outbound connection, so it needs no CA bundle and no
# resolver. Three things decided it the other way, for roughly a megabyte:
#
#  1. /tmp exists. SQLite spills to a temporary directory for sorts and temp
#     tables that do not fit its cache, and finds it via TMPDIR falling back to
#     /tmp. On scratch there is no /tmp, and the failure would not be a startup
#     error an operator sees immediately — it would be an occasional 500 on a
#     wide §5.3 prefix scan, months later, on a busy instance.
#  2. /etc/passwd and /etc/group carry the nonroot entry, so the process has a
#     resolvable identity rather than a bare uid. On scratch, USER 65532 names
#     nobody and anything that looks up the current user fails.
#  3. Zone data and a CA bundle are present. This binary needs neither today.
#     They cost almost nothing and they remove a class of surprise from any
#     future change.
#
# What matters is what it does NOT add: no shell, no package manager, no
# busybox, no coreutils. There is nothing in this image to get a prompt from.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="trigstationd" \
      org.opencontainers.image.description="Trigstation directory service — a zero-knowledge coordination service for self-hosted media servers." \
      org.opencontainers.image.source="https://github.com/trigstation/trigstationd" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# AGPL §4: a copy of the licence travels with the program.
COPY --from=build /src/LICENSE /LICENSE

COPY --from=build /out/trigstationd /usr/local/bin/trigstationd

# Creates /data, owned 65532:65532 and mode 0700. See the build stage.
COPY --from=build /out/rootfs/ /

# Defaults are set as environment variables rather than as CMD arguments, and
# deliberately. Every flag has an environment fallback (see main.go), so an
# operator can append flags to `docker run` without silently losing the database
# path — which is what would happen if these were a CMD that the extra arguments
# replaced.
ENV TRIGSTATIOND_LISTEN=":8080" \
    TRIGSTATIOND_DB="/data/trigstation.db"

# Plain HTTP. TLS is terminated by the reverse proxy in front (§9), and a
# directory that also spoke TLS would be a second certificate to renew for no
# gain.
EXPOSE 8080

# No VOLUME instruction. docker-compose.yml mounts a named volume at /data;
# declaring one here as well would mean every throwaway `docker run` leaves an
# anonymous volume behind that nobody ever reclaims.

# Non-root, by number. The name would work — distroless has the passwd entry —
# but a numeric uid is what an orchestrator's runAsNonRoot check can verify
# without resolving anything.
USER 65532:65532

# No healthcheck here: there is no shell in this image to run one with. The
# compose file checks GET /v1/meta from the proxy container instead. There is no
# /health endpoint and there must not be one — the API stays at four operations
# (§10).

ENTRYPOINT ["/usr/local/bin/trigstationd"]
