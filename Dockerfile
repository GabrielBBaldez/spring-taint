# Build stage: produce the self-contained analyzer jar.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml ./
COPY config ./config
COPY spring-taint-engine ./spring-taint-engine
COPY spring-taint-benchmark ./spring-taint-benchmark
RUN mvn -q -B -ntp -pl spring-taint-engine -am package -DskipTests

# Runtime stage. JDK 17: Tai-e 0.5.1's frontend cannot read JDK 21 bytecode,
# so the analysis must run on a Java 17 runtime.
FROM eclipse-temurin:17-jdk-jammy
LABEL org.opencontainers.image.title="Spring Taint Analyzer"
LABEL org.opencontainers.image.description="Interprocedural taint analysis for Spring Boot, built on Tai-e"
LABEL org.opencontainers.image.source="https://github.com/GabrielBBaldez/spring-taint"
WORKDIR /opt/spring-taint
COPY --from=build /src/spring-taint-engine/target/spring-taint-all.jar ./spring-taint.jar
COPY --from=build /src/config ./config
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["/opt/spring-taint/entrypoint.sh"]
