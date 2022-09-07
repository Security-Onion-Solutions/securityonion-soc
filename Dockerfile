# Copyright Jason Ertel (github.com/jertel).
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

FROM ghcr.io/security-onion-solutions/golang:alpine as builder
ARG VERSION=0.0.0
RUN apk update && apk add libpcap-dev bash git musl-dev gcc npm python3 py3-pip
COPY . /build
WORKDIR /build
RUN npm install jest jest-environment-jsdom --global
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN ./build.sh "$VERSION"

FROM ghcr.io/security-onion-solutions/python:3-slim

ARG UID=939
ARG GID=939
ARG VERSION=0.0.0
ARG ELASTIC_VERSION=0.0.0
ARG WAZUH_VERSION=0.0.0

RUN apt update -y && apt install -y bash tzdata ca-certificates wget curl tcpdump unzip && update-ca-certificates
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
RUN find html/js -name "*test*.js" -delete
RUN chmod u+x scripts/*
RUN chown 939:939 scripts/*
RUN find . -name \*.html -exec sed -i -e "s/VERSION_PLACEHOLDER/$VERSION/g" {} \;

RUN bash -c "[[ $ELASTIC_VERSION == '0.0.0' ]]" || \
    (mkdir -p html/downloads && \
     wget https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-oss-$(echo $ELASTIC_VERSION)-windows-x86_64.msi -P html/downloads/ && \
     wget https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-oss-$(echo $ELASTIC_VERSION)-x86_64.rpm -P html/downloads/ && \
     wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-$(echo $ELASTIC_VERSION)-x86_64.rpm -P html/downloads/ && \
     wget https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-oss-$(echo $ELASTIC_VERSION)-x86_64.rpm -P html/downloads/ && \
     wget https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-oss-$(echo $ELASTIC_VERSION)-amd64.deb -P html/downloads/ && \
     wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-$(echo $ELASTIC_VERSION)-amd64.deb -P html/downloads/ && \
     wget https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-oss-$(echo $ELASTIC_VERSION)-amd64.deb -P html/downloads/)

RUN bash -c "[[ $WAZUH_VERSION == '0.0.0' ]]" || \
    (mkdir -p html/downloads && \
     wget https://packages.wazuh.com/3.x/osx/wazuh-agent-$(echo $WAZUH_VERSION).pkg -P html/downloads/ && \
     wget https://packages.wazuh.com/3.x/yum/wazuh-agent-$(echo $WAZUH_VERSION).x86_64.rpm -P html/downloads/ && \
     wget https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-agent/wazuh-agent_$(echo $WAZUH_VERSION)_amd64.deb -P html/downloads/ && \
     wget https://packages.wazuh.com/3.x/windows/wazuh-agent-$(echo $WAZUH_VERSION).msi -P html/downloads/)

RUN bash -c "[[ $VERSION == '0.0.0' ]]" || \
    (wget https://docs.securityonion.net/_/downloads/en/$(echo $VERSION | cut -d'.' -f 1,2)/htmlzip/ -O /tmp/docs.zip && \
    unzip -o /tmp/docs.zip -d html/docs && \
    rm -f /tmp/docs.zip && \
    mv -f html/docs/securityonion-*/* html/docs && \
    rm -fr html/docs/securityonion-* && \
    wget https://github.com/Security-Onion-Solutions/securityonion-docs/raw/$(echo $VERSION | cut -d'.' -f 1,2)/images/cheat-sheet/Security-Onion-Cheat-Sheet.pdf -O html/docs/cheatsheet.pdf)

ENV ELASTIC_VERSION=$ELASTIC_VERSION
ENV WAZUH_VERSION=$WAZUH_VERSION

USER socore
EXPOSE 9822/tcp
VOLUME /opt/sensoroni/jobs
VOLUME /opt/sensoroni/logs
ENTRYPOINT ["/opt/sensoroni/sensoroni"]
