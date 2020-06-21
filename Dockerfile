# Copyright 2019 Jason Ertel (jertel). All rights reserved.
#
# This program is distributed under the terms of version 2 of the
# GNU General Public License.  See LICENSE for further details.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

FROM golang:alpine as builder
ARG VERSION=0.0.0
RUN apk update && apk add libpcap-dev bash git musl-dev gcc
COPY . /build
WORKDIR /build
RUN ./build.sh "$VERSION"

FROM alpine:latest
ARG UID=939
ARG GID=939
ARG VERSION=0.0.0
RUN apk update && apk add tzdata ca-certificates curl tcpdump && update-ca-certificates
RUN addgroup --gid "$GID" socore
RUN adduser -D -u "$UID" -G socore -g '' socore
RUN mkdir -p /opt/sensoroni/jobs && chown socore:socore /opt/sensoroni/jobs
RUN mkdir -p /opt/sensoroni/logs && chown socore:socore /opt/sensoroni/logs
WORKDIR /opt/sensoroni
COPY --from=builder /build/sensoroni .
COPY --from=builder /build/scripts ./scripts
COPY --from=builder /build/html ./html
COPY --from=builder /build/COPYING .
COPY --from=builder /build/LICENSE .
COPY --from=builder /build/README.md .
COPY --from=builder /build/sensoroni.json .
RUN chmod u+x scripts/*
RUN find . -name \*.html -exec sed -i -e "s/VERSION_PLACEHOLDER/$VERSION/g" {} \;
USER socore
EXPOSE 9822/tcp
VOLUME /opt/sensoroni/jobs
VOLUME /opt/sensoroni/logs
ENTRYPOINT ["/opt/sensoroni/sensoroni"]
