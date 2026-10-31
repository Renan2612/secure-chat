// Autorização por sala (item D do baseline — IDOR): só deixa passar quem
// consta em rooms_users para a sala pedida. A sala vem de :id, :room ou do
// campo "room" do corpo, conforme a rota. Sala inexistente e sala alheia
// recebem a MESMA resposta 403, para não revelar quais IDs de sala existem.
// Deve rodar depois do requireAuth (depende de req.session.userId).
const pool = require("../db");

// SÓ PARA A MUTAÇÃO (i) do scripts/compare/attack-matrix.sh: com este valor
// EXATO, a checagem de pertencimento à sala é pulada (quebra a autorização
// de propósito, para provar que a matriz percebe). Nunca ativa por padrão; o
// server.js avisa no log ao subir. Mesma convenção dos outros E2EE_TEST_*.
const { honored } = require("../config/testFlags");
const SKIP_VALUE = "inseguro-so-para-teste";
// Só tem efeito em NODE_ENV=test (config/testFlags.js).
const skipForTest = () => honored("TEST_SKIP_ROOM_MEMBER", SKIP_VALUE);

const roomIdFrom = (req) => {
  const raw = req.params.id ?? req.params.room ?? req.body?.room;
  const id = Number(raw);
  return Number.isSafeInteger(id) && id > 0 && String(raw) === String(id) ? id : null;
};

const requireRoomMember = async (req, res, next) => {
  if (skipForTest()) return next();
  const roomId = roomIdFrom(req);
  if (roomId === null) {
    return res.status(400).json({ message: "Requisição inválida" });
  }
  try {
    const { rowCount } = await pool.query(
      "SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2",
      [roomId, req.session.userId]
    );
    if (rowCount === 0) {
      return res.status(403).json({ message: "Acesso negado" });
    }
    return next();
  } catch (err) {
    return next(err);
  }
};

module.exports = requireRoomMember;
