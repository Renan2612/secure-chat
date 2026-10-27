// Constantes do protocolo de tempo real do secure-chat (docs/03-protocolo.md).

const PROTOCOL_PATH = "/ws";

const DEFAULT_LIMITS = {
  maxConnectionsPerUser: 5,
  maxConnections: 1000,
};

module.exports = { PROTOCOL_PATH, DEFAULT_LIMITS };
