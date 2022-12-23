FROM openjdk:11-jre-slim-buster
ADD target/tw-transformation-api-1.0.0-jar-with-dependencies.jar ./
RUN apt update -o Acquire::Check-Valid-Until=false -o Acquire::Check-Date=false

ENTRYPOINT ["java","-jar","tw-transformation-api-1.0.0-jar-with-dependencies.jar"]
