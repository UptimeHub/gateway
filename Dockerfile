FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

ARG JAR_FILE=target/*.jar

COPY ${JAR_FILE} app.jar

RUN chown -R app:app /app

USER app

ENTRYPOINT ["java", "-jar", "/app/app.jar"]