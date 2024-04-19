# Copyright 2019 Jason Ertel (github.com/jertel).
# Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

FROM ghcr.io/security-onion-solutions/golang:1.21.5-alpine as builder
ARG VERSION=0.0.0
RUN apk update && apk add libpcap-dev bash git musl-dev gcc npm python3 py3-pip py3-virtualenv python3-dev openssl-dev linux-headers
COPY . /build
WORKDIR /build
RUN if [ "$VERSION" != "0.0.0" ]; then mkdir gitdocs && cd gitdocs && \
	git clone --no-single-branch --depth 50 https://github.com/Security-Onion-Solutions/securityonion-docs.git . && \
	git checkout --force origin/$(echo $VERSION | cut -d'.' -f1,2) && \
	git clean -d -f -f && \
	sed -i "s|'display_github': True|'display_github': False|g" conf.py && \
	python3 -mvirtualenv /tmp/virtualenv && \
	/tmp/virtualenv/bin/python -m pip install --exists-action=w --no-cache-dir -r requirements.txt && \
	for i in /tmp/virtualenv/lib/python*/site-packages/sphinx_rtd_theme/versions.html; do echo > $i; done && \
	/tmp/virtualenv/bin/python -m sphinx -T -E -b html -d _build/doctrees -D language=en . _build/html; \
	else mkdir -p gitdocs/_build/html; fi
RUN npm install jest jest-environment-jsdom --global
RUN ./build.sh "$VERSION"

RUN pip3 install sigma-cli pysigma-backend-elasticsearch pysigma-pipeline-windows --break-system-packages
RUN sed -i 's/#!\/usr\/bin\/python3/#!\/usr\/bin\/env python/g' /usr/bin/sigma

# Build specific version of yara-python - needs to be pinned to Strelka's version.
FROM ghcr.io/security-onion-solutions/python:3-slim as stage_2
RUN apt-get update && apt-get install -y gcc python3-dev libssl-dev
RUN pip3 install yara-python==4.3.1

FROM ghcr.io/security-onion-solutions/python:3-slim

ARG UID=939
ARG GID=939
ARG VERSION=0.0.0
ARG ELASTIC_VERSION=0.0.0
ARG WAZUH_VERSION=0.0.0

RUN apt update -y
RUN apt install -y bash tzdata ca-certificates wget curl tcpdump unzip
RUN update-ca-certificates
RUN addgroup --gid "$GID" socore
RUN adduser --disabled-password --uid "$UID" --ingroup socore --gecos '' socore
RUN mkdir -p /opt/sensoroni/jobs && chown socore:socore /opt/sensoroni/jobs
RUN mkdir -p /opt/sensoroni/logs && chown socore:socore /opt/sensoroni/logs
WORKDIR /opt/sensoroni
COPY --from=builder /build/sensoroni .
COPY --from=builder /build/scripts ./scripts
COPY --from=builder /build/html ./html
COPY --from=builder /build/rbac ./rbac
COPY --from=builder /build/LICENSE .
COPY --from=builder /build/README.md .
COPY --from=builder /build/sensoroni.json .
COPY --from=builder /build/gitdocs/_build/html ./html/docs
COPY --from=builder /usr/lib/python3.11/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/bin/sigma /usr/bin/sigma
COPY --from=stage_2 /usr/local/lib/python3.9/site-packages/yara_python-4.3.1.dist-info /usr/local/lib/python3.9/site-packages/
COPY --from=stage_2 /usr/local/lib/python3.9/site-packages/yara.cpython-39-x86_64-linux-gnu.so /usr/local/lib/python3.9/site-packages/
RUN find html/js -name "*test*.js" -delete
RUN chmod u+x scripts/*
RUN chown 939:939 scripts/*
RUN find . -name \*.html -exec sed -i -e "s/VERSION_PLACEHOLDER/$VERSION/g" {} \;

RUN bash -c "[[ $VERSION == '0.0.0' ]]" || \
    wget https://github.com/Security-Onion-Solutions/securityonion-docs/raw/$(echo $VERSION | cut -d'.' -f 1,2)/images/cheat-sheet/Security-Onion-Cheat-Sheet.pdf -O html/docs/cheatsheet.pdf

ENV ELASTIC_VERSION=$ELASTIC_VERSION
ENV WAZUH_VERSION=$WAZUH_VERSION

USER socore
EXPOSE 9822/tcp

ENTRYPOINT ["/opt/sensoroni/sensoroni"]
