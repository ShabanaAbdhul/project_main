create table users(
id int auto_increment PRIMARY KEY,
username varchar(50) not null,
email varchar(100) not null unique,
password varchar(255) not null
);

CREATE TABLE notes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
