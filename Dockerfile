FROM eclipse-temurin:11-jre
WORKDIR /app
COPY target/java-sec-code-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
