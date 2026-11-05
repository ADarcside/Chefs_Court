import { PAGINATION } from "../constants.js";

/** Escapes a string so it matches literally inside a RegExp. */
export function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Case-insensitive "contains" regex built from untrusted input. */
export function containsRegex(value) {
  return new RegExp(escapeRegex(String(value).slice(0, 100)), "i");
}

/** Parses ?page and ?limit into safe integers. */
export function parsePagination(query) {
  const page = Math.max(1, Number.parseInt(query.page, 10) || 1);
  const requested = Number.parseInt(query.limit, 10) || PAGINATION.DEFAULT_LIMIT;
  const limit = Math.min(PAGINATION.MAX_LIMIT, Math.max(1, requested));
  return { page, limit, skip: (page - 1) * limit };
}
