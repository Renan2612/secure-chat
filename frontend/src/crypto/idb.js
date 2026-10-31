// IndexedDB mínimo (promessas): um banco, um object store de registros
// { key, value }. Só guarda o que já chega SELADO (vault.js).
const DB_NAME = "secure-chat";
const STORE = "vault";

let opening = null;

const db = () => {
  if (!opening) {
    opening = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => {
        opening = null; // a próxima chamada tenta abrir de novo (sem isso, tudo falharia até recarregar)
        reject(req.error);
      };
    });
  }
  return opening;
};

const run = async (mode, fn) => {
  const tx = (await db()).transaction(STORE, mode);
  const result = fn(tx.objectStore(STORE));
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve(result?.result);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
};

export const idbGet = (key) => run("readonly", (store) => store.get(key));
// Vários registros numa transação só: ou todos são gravados, ou nenhum.
export const idbPutMany = (entries) =>
  run("readwrite", (store) => {
    for (const [key, value] of entries) store.put(value, key);
  });
export const idbDelete = (keys) =>
  run("readwrite", (store) => {
    for (const key of keys) store.delete(key);
  });
