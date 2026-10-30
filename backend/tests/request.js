// supertest com o cabeçalho Origin da própria origem (CLIENT_URL) em toda
// requisição, como faz um navegador na página do chat: desde a Etapa 5
// (A2), POST/PUT/DELETE sem Origin ou de outro site recebem 403. Um teste
// pode trocá-lo (.set("Origin", ...)) ou tirá-lo (.unset("Origin")).
const supertest = require("supertest");

const METHODS = new Set(["get", "post", "put", "patch", "delete", "head"]);

const withOrigin = (target) =>
  new Proxy(target, {
    get(obj, prop) {
      const value = obj[prop];
      if (METHODS.has(prop)) return (...args) => value.apply(obj, args).set("Origin", process.env.CLIENT_URL);
      return typeof value === "function" ? value.bind(obj) : value;
    },
  });

const request = (app) => withOrigin(supertest(app));
request.agent = (app, options) => withOrigin(supertest.agent(app, options));

module.exports = request;
