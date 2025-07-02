select *from usuarios;
INSERT INTO usuario (username, password_hash) VALUES (
  'admin',
  '$pbkdf2:sha256:260000$xxxxxx$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
);
