// Núcleo isomórfico da E2EE do secure-chat (docs/05-e2ee.md). Só Web Crypto,
// TextEncoder e btoa/atob: roda no Node ≥ 19 e no navegador. O que depende
// de Node (arquivos, permissões) fica em ./node.js.
const encoding = require("./encoding");
const primitives = require("./primitives");
const identity = require("./identity");
const roomKeys = require("./roomKeys");
const messages = require("./messages");
const keystore = require("./keystore");
const trust = require("./trust");
const receiver = require("./receiver");
const roomName = require("./roomName");
const { E2eeError } = require("./errors");

module.exports = { ...identity, ...roomKeys, ...messages, ...keystore, ...trust, ...receiver, ...roomName, encoding, primitives, E2eeError };
