// Apaga do banco de desenvolvimento TUDO o que o teste criou (usuários
// e2e-*@example.invalid, as salas deles e o que depende delas).
import { execFileSync } from "node:child_process";
import { join } from "node:path";

const SQL = `
WITH u AS (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid'),
     r AS (SELECT id AS room FROM rooms WHERE created_by IN (SELECT id FROM u) OR owner_id IN (SELECT id FROM u)
           UNION SELECT room FROM rooms_users WHERE user_id IN (SELECT id FROM u))
DELETE FROM rooms WHERE id IN (SELECT room FROM r);
DELETE FROM room_key_wraps WHERE recipient_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid') OR sender_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM room_key_versions WHERE created_by IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM messages WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM rooms_users WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM room_bans WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM user_sessions WHERE (sess->>'userId')::int IN (SELECT id FROM users WHERE email LIKE 'e2e-%@example.invalid');
DELETE FROM users WHERE email LIKE 'e2e-%@example.invalid';
SELECT COUNT(*) FROM users WHERE email LIKE 'e2e-%@example.invalid';`;

export default () => {
  const root = join(import.meta.dirname, "..", "..");
  const left = execFileSync(
    "docker",
    ["compose", "--env-file", "backend/.env", "exec", "-T", "db", "psql", "-U", process.env.DB_USER || "postgres", "-d", process.env.DB_NAME || "secure_chat", "-v", "ON_ERROR_STOP=1", "-qAt"],
    { cwd: root, input: SQL }
  ).toString().trim();
  if (left !== "0") throw new Error(`usuários de teste ainda no banco: ${left}`);
  console.log("(usuários, salas e mensagens do teste removidos do banco)");
};
