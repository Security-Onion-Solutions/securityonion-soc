# Copyright 2019 Jason Ertel (github.com/jertel).
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

FROM ghcr.io/security-onion-solutions/golang:1.25.1-alpine as builder
ARG VERSION=0.0.0
ARG ALT_BRANCH=dev
ARG REVKEYS=
RUN apk update && apk add libpcap-dev bash git musl-dev gcc npm python3 py3-pip py3-virtualenv python3-dev openssl-dev linux-headers
COPY . /build

# Mock md2pdf script for testing
RUN echo "#!/bin/sh" > /build/scripts/md2pdf && \
	echo "echo 'Helvetica' > /tmp/0.pdf" >> /build/scripts/md2pdf && \
	chmod u+x /build/scripts/md2pdf

WORKDIR /build
RUN if [ "$VERSION" != "0.0.0" ]; then mkdir gitdocs && cd gitdocs && \
	git clone --no-single-branch --depth 50 https://github.com/Security-Onion-Solutions/securityonion-docs.git . && \
	git checkout --force origin/${ALT_BRANCH} && \
	git clean -d -f -f && \
	sed -i "s|'display_github': True|'display_github': False|g" conf.py && \
	python3 -mvirtualenv /tmp/virtualenv && \
	/tmp/virtualenv/bin/python -m pip install --exists-action=w --no-cache-dir -r requirements.txt && \
	for i in /tmp/virtualenv/lib/python*/site-packages/sphinx_rtd_theme/versions.html; do echo > $i; done && \
	mkdir -p specs && \
	cd .. && \
	go install github.com/swaggo/swag/v2/cmd/swag@latest && \
	swag init -g server/server.go --md docs/api --v3.1 -ot yaml -o gitdocs/specs && \
	cd gitdocs && \
	mv specs/swagger.yaml specs/openapi.yaml && \
	/tmp/virtualenv/bin/python -m sphinx -T -E -b html -d _build/doctrees -D language=en . _build/html; \
	else mkdir -p gitdocs/_build/html; fi
RUN npm install jest jest-environment-jsdom --global
RUN ./build.sh "$VERSION"


FROM ghcr.io/security-onion-solutions/python:3.13.7-slim

ARG UID=939
ARG GID=939
ARG VERSION=0.0.0
ARG ELASTIC_VERSION=0.0.0
ARG WAZUH_VERSION=0.0.0

RUN apt update -y && apt upgrade -y
RUN apt install -y --no-install-recommends bash tzdata ca-certificates wget curl tcpdump unzip git gcc python3-dev libssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip3 install pysigma==0.11.20 sigma-cli==1.0.5 pysigma-backend-elasticsearch pysigma-pipeline-windows --break-system-packages
ADD dep/pysigma_backend_securityonion-0.1.0-py3-none-any.whl /tmp
RUN pip3 install /tmp/pysigma_backend_securityonion-0.1.0-py3-none-any.whl
RUN pip3 install yara-python==4.3.1
RUN apt-get -y remove gcc python3-dev libssl-dev && apt-get -y autoremove
RUN rm /tmp/pysigma_backend_securityonion-0.1.0-py3-none-any.whl

RUN update-ca-certificates
RUN addgroup --gid "$GID" socore
RUN adduser --disabled-password --uid "$UID" --ingroup socore --gecos '' socore
RUN mkdir -p /opt/sensoroni/jobs && chown socore:socore /opt/sensoroni/jobs
RUN mkdir -p /opt/sensoroni/logs && chown socore:socore /opt/sensoroni/logs
WORKDIR /opt/sensoroni
COPY --from=builder /build/sensoroni .
COPY scripts ./scripts
COPY --from=builder /build/html ./html
COPY --from=builder /build/rbac ./rbac
COPY --from=builder /build/LICENSE .
COPY --from=builder /build/README.md .
COPY --from=builder /build/sensoroni.json .
COPY --from=builder /build/gitdocs/_build/html ./html/docs
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
