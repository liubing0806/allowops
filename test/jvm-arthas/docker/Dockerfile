# Sample target image. BASE selects the JDK/JRE; the application is the same everywhere.
ARG BASE=eclipse-temurin:17-jdk
FROM ${BASE}
ARG APP_UID=10001
# `app` has a passwd entry and a home directory. The no-HOME variant runs the same image under
# another uid that has no passwd entry (see compose.yaml).
RUN useradd -u ${APP_UID} -m -s /usr/sbin/nologin app
COPY app/target/app.jar /app/app.jar
COPY probe/probe.jar /app/probe.jar
COPY docker/entrypoint.sh /app/entrypoint.sh
WORKDIR /app
USER app
ENTRYPOINT ["/app/entrypoint.sh"]
