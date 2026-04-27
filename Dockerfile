FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY target/gateway-0.0.1-SNAPSHOT.jar app.jar

RUN chown -R app:app /app

USER app

ENTRYPOINT ["java", "-jar", "app.jar"]