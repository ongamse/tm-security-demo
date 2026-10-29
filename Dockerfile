FROM eclipse-temurin:11-jre-noble
WORKDIR /app
COPY target/java-sec-code-1.0.0.jar app.jar
RUN groupadd --system app && useradd --system --gid app --no-create-home --shell /usr/sbin/nologin app
USER app
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
