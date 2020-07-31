FROM openjdk:12
VOLUME /tmp
WORKDIR '/app'
EXPOSE 8090
COPY . .
RUN ./mvnw clean install 
ENTRYPOINT java  -jar /app/target/zuul-server-0.0.1-SNAPSHOT.jar