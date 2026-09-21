// src/http/request-body.js
// Single concern: safely reading and parsing a JSON request body, with a
// hard size cap so no other module needs to think about this again.
"use strict";

const MAX_BODY_BYTES = 100_000;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    let tooLarge = false;
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooLarge) return reject(new Error("payload too large"));
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

module.exports = { readBody };
