
# Get the builder image
FROM maven:3.9-eclipse-temurin-24
COPY . /build
WORKDIR /build
# Build the app
# Artifact will be stored at /build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar
RUN mvn package

# Build the image with the new .jar binary
FROM openjdk:24-slim
ARG GIT_COMMIT=unspecified
ARG GIT_TAG=unspecified
LABEL org.opencontainers.image.authors="Besmir Zanaj"
LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.version="$GIT_TAG"
COPY --from=0 /build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar ./json-web-key-generator.jar
ENTRYPOINT ["java", "-jar", "json-web-key-generator.jar"]
