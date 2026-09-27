FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.work .
COPY apps/api/go.mod ./apps/api/
COPY apps/agent/go.mod ./apps/agent/
COPY apps/api ./apps/api
RUN cd apps/api && go mod download && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/ucsi ./cmd/ucsi && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/ucsi-worker ./cmd/ucsi-worker && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/ucsi-scheduler ./cmd/ucsi-scheduler && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/ucsi-cli ./cmd/ucsi-cli

FROM alpine:3.22 AS api
RUN adduser -D -H -u 10001 ucsi
USER 10001
COPY --from=build /out/ucsi /ucsi
EXPOSE 8080
ENTRYPOINT ["/ucsi"]

FROM alpine:3.22 AS scheduler
RUN adduser -D -H -u 10001 ucsi
USER 10001
COPY --from=build /out/ucsi-scheduler /ucsi-scheduler
ENTRYPOINT ["/ucsi-scheduler"]

FROM alpine:3.22 AS worker
RUN adduser -D -H -u 10001 ucsi
USER 10001
COPY --from=build /out/ucsi-worker /ucsi-worker
ENTRYPOINT ["/ucsi-worker"]

FROM alpine:3.22 AS cli
RUN adduser -D -H -u 10001 ucsi
USER 10001
COPY --from=build /out/ucsi-cli /ucsi-cli
ENTRYPOINT ["/ucsi-cli"]
