FROM mariadb:10.11.19@sha256:7d829180b5b2a9ba74f6242876ab401a0d7dd338a807e522ef92bc9698760f20
COPY seed.sh /docker-entrypoint-initdb.d/01-east-quay.sh
RUN chmod 0755 /docker-entrypoint-initdb.d/01-east-quay.sh
