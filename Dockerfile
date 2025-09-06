# Build stage
FROM maven:3.9.6-eclipse-temurin-24 AS build
COPY . /app
WORKDIR /app
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:24-jre
COPY --from=build /app/target/*.jar /app/app.jar
EXPOSE 8080
CMD ["java", "-Dspring.profiles.active=prod", "-jar", "/app/app.jar"]
