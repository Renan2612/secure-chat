DELETE FROM messages;
DELETE FROM rooms_users;
DELETE FROM users;
DELETE FROM rooms;

INSERT INTO users(name, email, password) VALUES('Test 1', 'test@test.com', '12345');
INSERT INTO users(name, email, password) VALUES('Test 2', 'test2@test.com', '12345');

INSERT INTO rooms(name, key) VALUES('Sala 1', '1');
INSERT INTO rooms(name, key) VALUES('Sala 2', '2');

INSERT INTO rooms_users(room, user_id) VALUES (1,1);
INSERT INTO rooms_users(room, user_id) VALUES (1,2);
INSERT INTO rooms_users(room, user_id) VALUES (2,1);

INSERT INTO messages(room, user_id, message, dt_message) VALUES (1,1,'Message 1 - Room 1','2022-10-25 10:35PM');
INSERT INTO messages(room, user_id, message, dt_message) VALUES (2,1,'Message 1 - Room 2','2022-10-25 10:38PM');
INSERT INTO messages(room, user_id, message, dt_message) VALUES (1,2,'Message 2 - Room 1','2022-10-25 10:45PM');