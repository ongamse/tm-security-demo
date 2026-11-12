FROM eclipse-temurin:11-jre-jammy
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app \
    && mkdir -p /app \
    && chown app:app /app
WORKDIR /app
COPY --chown=app:app target/java-sec-code-1.0.0.jar app.jar
USER app
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
