FROM eclipse-temurin:11-jre
WORKDIR /app
COPY target/java-sec-code-1.0.0.jar app.jar
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser && \
    chown -R appuser:appuser /app
EXPOSE 8080
USER appuser
ENTRYPOINT ["java","-jar","/app/app.jar"]
