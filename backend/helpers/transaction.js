// Roda `work(client)` numa transação, com o mesmo cuidado do createRooms:
// listener de 'error' no client (uma queda de conexão no meio da transação,
// sem listener, derrubaria o processo), ROLLBACK em qualquer erro e descarte
// da conexão se ela quebrou.
const pool = require("../db");

const withTransaction = async (work) => {
  let brokenConnection;
  const onConnectionError = (connErr) => {
    brokenConnection = connErr;
  };
  const client = await pool.connect();
  client.on("error", onConnectionError);
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    if (!brokenConnection) {
      await client.query("ROLLBACK").catch((rollbackErr) => {
        console.error("[erro] ROLLBACK falhou:", rollbackErr.message);
        brokenConnection = rollbackErr;
      });
    }
    throw err;
  } finally {
    client.removeListener("error", onConnectionError);
    client.release(brokenConnection);
  }
};

module.exports = { withTransaction };
