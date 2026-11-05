export const ROLES = Object.freeze({
  DEFENDANT: "DEFENDANT",
  PLAINTIFF: "PLAINTIFF",
  JUROR: "JUROR",
  JUDGE: "JUDGE",
});

/** Roles allowed to file a case. */
export const PARTY_ROLES = Object.freeze([ROLES.DEFENDANT, ROLES.PLAINTIFF]);

export const CASE_STATUS = Object.freeze({
  PENDING: "PENDING",
  APPROVED: "APPROVED",
  REJECTED: "REJECTED",
  CLOSED: "CLOSED",
});

/** Statuses a judge may set directly (CLOSED is only reached via a verdict). */
export const EDITABLE_STATUSES = Object.freeze([
  CASE_STATUS.PENDING,
  CASE_STATUS.APPROVED,
  CASE_STATUS.REJECTED,
]);

/** Statuses whose cases (and results) are visible to jurors. */
export const JUROR_VISIBLE_STATUSES = Object.freeze([CASE_STATUS.APPROVED, CASE_STATUS.CLOSED]);

export const VOTE = Object.freeze({
  GUILTY: "guilty",
  NOT_GUILTY: "not_guilty",
});

export const VOTE_CHOICES = Object.freeze(Object.values(VOTE));

export const MIN_PASSWORD_LENGTH = 8;

export const UPLOAD = Object.freeze({
  MAX_FILES: 5,
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10 MB
  ALLOWED_MIME_TYPES: ["application/pdf", "image/png", "image/jpeg", "text/plain"],
});

export const PAGINATION = Object.freeze({
  DEFAULT_LIMIT: 20,
  MAX_LIMIT: 100,
});
