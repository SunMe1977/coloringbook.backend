CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    image_url VARCHAR(255),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password VARCHAR(255),
    provider VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255)
);
