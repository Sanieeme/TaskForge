// src/validation/validators.js
// Single concern: is this input shaped correctly? These functions have no
// knowledge of HTTP, the database, or what happens to a value once it
// passes - they only answer true/false about the input itself.
"use strict";

function isValidUsername(u) {
  return typeof u === "string" && /^[a-zA-Z0-9_]{3,32}$/.test(u);
}

function isValidPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 200;
}

function isValidRole(r) {
  return r === "employee"; // self-registration can only ever create employees
}

module.exports = { isValidUsername, isValidPassword, isValidRole };
