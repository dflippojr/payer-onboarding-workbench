# Upstream's Dockerfile (HL7-DaVinci/CRD) with one change: CDS-Library is checked out
# at CDS_LIBRARY_COMMIT instead of master. The build context is the CRD repository at
# CRD_COMMIT; scripts/crd-reference-server.sh passes both from crd-reference-server.env.
FROM amazoncorretto:17-alpine-jdk AS builder
ARG CDS_LIBRARY_COMMIT
RUN apk add --no-cache git bash
WORKDIR /CRD
COPY . .
RUN test -n "$CDS_LIBRARY_COMMIT" \
 && ./gradlew --no-daemon --no-parallel :server:embedCdsLibrary -Pbranch="$CDS_LIBRARY_COMMIT"
RUN ./gradlew --no-daemon --no-parallel build -x checkstyleMain -x checkstyleTest -x test

FROM amazoncorretto:17-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /CRD/server/build/libs/*.jar app.jar
COPY --from=builder --chown=appuser:appgroup /CRD/server/CDS-Library ./CDS-Library/
RUN mkdir -p /app/ValueSetCache && chown appuser:appgroup /app/ValueSetCache
EXPOSE 8090
USER appuser
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
