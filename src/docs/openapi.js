import { CASE_STATUS, ROLES, VOTE_CHOICES } from "../constants.js";

const bearer = [{ bearerAuth: [] }];
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema) => ({ "application/json": { schema } });
const errorResponse = (description) => ({ description, content: json(ref("Error")) });
const idParam = (name, description) => ({
  name,
  in: "path",
  required: true,
  description,
  schema: { type: "string", pattern: "^[a-f0-9]{24}$" },
});

const common = {
  400: errorResponse("Bad request"),
  401: errorResponse("Missing or invalid token"),
  403: errorResponse("Insufficient role"),
  404: errorResponse("Not found"),
};

const judgeAction = (operationId, summary, description) => ({
  tags: ["Cases"],
  operationId,
  summary,
  description,
  security: bearer,
  parameters: [idParam("id", "Case ID")],
  responses: {
    200: { description: "Updated case", content: json(ref("Case")) },
    ...common,
    409: errorResponse("Case is closed"),
  },
});

export const openapiSpec = {
  openapi: "3.0.3",
  info: {
    title: "Chef's Court API",
    version: "1.1.0",
    description:
      "A courtroom for kitchen disputes. Plaintiffs and defendants file cases, " +
      "judges approve and rule on them, and jurors vote.\n\n" +
      "Authenticate with `POST /auth/login`, then click **Authorize** and paste the token.",
  },
  servers: [{ url: "/" }],
  tags: [
    { name: "Health" },
    { name: "Auth" },
    { name: "Cases" },
    { name: "Jury" },
    { name: "Uploads" },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
    schemas: {
      Error: {
        type: "object",
        properties: {
          error: { type: "string" },
          details: { type: "array", items: { type: "string" } },
        },
      },
      Role: { type: "string", enum: Object.values(ROLES) },
      CaseStatus: { type: "string", enum: Object.values(CASE_STATUS) },
      VoteChoice: { type: "string", enum: VOTE_CHOICES },
      User: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          email: { type: "string", format: "email" },
          role: ref("Role"),
        },
      },
      AuthResponse: {
        type: "object",
        properties: { token: { type: "string" }, user: ref("User") },
      },
      Verdict: {
        type: "object",
        properties: {
          outcome: ref("VoteChoice"),
          guilty: { type: "integer" },
          notGuilty: { type: "integer" },
          total: { type: "integer" },
          judgeOverride: { type: "boolean" },
          closedBy: { type: "string" },
          closedAt: { type: "string", format: "date-time" },
        },
      },
      Case: {
        type: "object",
        properties: {
          _id: { type: "string" },
          title: { type: "string" },
          partyType: { type: "string", enum: [ROLES.DEFENDANT, ROLES.PLAINTIFF] },
          partyName: { type: "string" },
          argumentText: { type: "string" },
          evidenceText: { type: "string" },
          evidenceFiles: { type: "array", items: { type: "string" } },
          status: ref("CaseStatus"),
          createdBy: { type: "string" },
          roleAtCreation: { type: "string" },
          verdict: { allOf: [ref("Verdict")], nullable: true },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
      },
      CasePage: {
        type: "object",
        properties: {
          data: { type: "array", items: ref("Case") },
          page: { type: "integer" },
          limit: { type: "integer" },
          total: { type: "integer" },
          totalPages: { type: "integer" },
        },
      },
      Vote: {
        type: "object",
        properties: {
          _id: { type: "string" },
          case: { type: "string" },
          juror: { type: "string" },
          choice: ref("VoteChoice"),
        },
      },
      Results: {
        type: "object",
        properties: {
          caseId: { type: "string" },
          status: ref("CaseStatus"),
          results: {
            type: "object",
            properties: {
              guilty: { type: "integer" },
              not_guilty: { type: "integer" },
              total: { type: "integer" },
            },
          },
          verdict: { allOf: [ref("Verdict")], nullable: true },
        },
      },
    },
  },
  paths: {
    "/health": {
      get: {
        tags: ["Health"],
        operationId: "health",
        summary: "Liveness check",
        responses: { 200: { description: "Service is up" } },
      },
    },
    "/auth/signup": {
      post: {
        tags: ["Auth"],
        operationId: "signup",
        summary: "Create an account",
        description:
          "Registering as `JUDGE` requires `inviteCode` matching the server's `JUDGE_INVITE_CODE`.",
        requestBody: {
          required: true,
          content: json({
            type: "object",
            required: ["name", "email", "password", "role"],
            properties: {
              name: { type: "string", example: "Jury Jane" },
              email: { type: "string", format: "email", example: "jury@example.com" },
              password: { type: "string", minLength: 8, example: "Passw0rd!" },
              role: ref("Role"),
              inviteCode: { type: "string", description: "Required for JUDGE" },
            },
          }),
        },
        responses: {
          201: { description: "Account created", content: json(ref("AuthResponse")) },
          400: common[400],
          403: errorResponse("Invalid judge invite code"),
          409: errorResponse("Email already registered"),
        },
      },
    },
    "/auth/login": {
      post: {
        tags: ["Auth"],
        operationId: "login",
        summary: "Log in and receive a JWT",
        requestBody: {
          required: true,
          content: json({
            type: "object",
            required: ["email", "password"],
            properties: {
              email: { type: "string", format: "email" },
              password: { type: "string" },
            },
          }),
        },
        responses: {
          200: { description: "Logged in", content: json(ref("AuthResponse")) },
          400: common[400],
          401: errorResponse("Invalid credentials"),
        },
      },
    },
    "/case/submit": {
      post: {
        tags: ["Cases"],
        operationId: "submitCase",
        summary: "File a case (plaintiff / defendant)",
        description: "Up to 5 evidence files (PDF, PNG, JPEG or plain text, max 10 MB each).",
        security: bearer,
        requestBody: {
          required: true,
          content: {
            "multipart/form-data": {
              schema: {
                type: "object",
                required: ["title", "partyName", "argumentText"],
                properties: {
                  title: { type: "string", example: "Stolen Pie" },
                  partyName: { type: "string", example: "Chef Luigi" },
                  argumentText: { type: "string", example: "I did not steal the pie." },
                  evidenceText: { type: "string", example: "Timestamped alibi." },
                  files: { type: "array", items: { type: "string", format: "binary" } },
                },
              },
            },
          },
        },
        responses: {
          201: { description: "Case filed (status PENDING)", content: json(ref("Case")) },
          ...common,
          413: errorResponse("File too large"),
        },
      },
    },
    "/case/all": {
      get: {
        tags: ["Cases"],
        operationId: "listCases",
        summary: "List cases (paginated)",
        description: "Jurors only see APPROVED and CLOSED cases.",
        security: bearer,
        parameters: [
          { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
          {
            name: "limit",
            in: "query",
            schema: { type: "integer", minimum: 1, maximum: 100, default: 20 },
          },
          { name: "status", in: "query", schema: ref("CaseStatus") },
          {
            name: "q",
            in: "query",
            description: "Search title or party name",
            schema: { type: "string" },
          },
        ],
        responses: {
          200: { description: "A page of cases", content: json(ref("CasePage")) },
          400: common[400],
          401: common[401],
          403: common[403],
        },
      },
    },
    "/case/by-name/{name}": {
      get: {
        tags: ["Cases"],
        operationId: "findCasesByName",
        summary: "Find approved cases by party name (juror)",
        security: bearer,
        parameters: [{ name: "name", in: "path", required: true, schema: { type: "string" } }],
        responses: {
          200: {
            description: "Matching cases",
            content: json({ type: "array", items: ref("Case") }),
          },
          401: common[401],
          403: common[403],
        },
      },
    },
    "/case/{id}": {
      get: {
        tags: ["Cases"],
        operationId: "getCase",
        summary: "Get one case",
        security: bearer,
        parameters: [idParam("id", "Case ID")],
        responses: { 200: { description: "The case", content: json(ref("Case")) }, ...common },
      },
    },
    "/case/edit/{id}": {
      patch: {
        ...judgeAction("editCase", "Edit a case (judge)"),
        requestBody: {
          content: json({
            type: "object",
            properties: {
              title: { type: "string" },
              partyName: { type: "string" },
              argumentText: { type: "string" },
              evidenceText: { type: "string" },
              partyType: { type: "string", enum: [ROLES.DEFENDANT, ROLES.PLAINTIFF] },
              status: { type: "string", enum: ["PENDING", "APPROVED", "REJECTED"] },
            },
          }),
        },
      },
    },
    "/case/delete/{id}": {
      delete: {
        tags: ["Cases"],
        operationId: "deleteCase",
        summary: "Delete a case and its votes and files (judge)",
        security: bearer,
        parameters: [idParam("id", "Case ID")],
        responses: { 200: { description: "Deleted" }, ...common },
      },
    },
    "/case/approve/{id}": {
      patch: judgeAction("approveCase", "Approve a case for jury voting (judge)"),
    },
    "/case/reject/{id}": { patch: judgeAction("rejectCase", "Reject a case (judge)") },
    "/case/close/{id}": {
      patch: {
        ...judgeAction(
          "closeCase",
          "Close voting and issue the verdict (judge)",
          "Defaults to the jury majority. Pass `verdict` to override or to break a tie.",
        ),
        requestBody: {
          content: json({ type: "object", properties: { verdict: ref("VoteChoice") } }),
        },
      },
    },
    "/jury/vote/{caseId}": {
      post: {
        tags: ["Jury"],
        operationId: "castVote",
        summary: "Cast a vote on an approved case (juror, once per case)",
        security: bearer,
        parameters: [idParam("caseId", "Case ID")],
        requestBody: {
          required: true,
          content: json({
            type: "object",
            required: ["choice"],
            properties: { choice: ref("VoteChoice") },
          }),
        },
        responses: {
          201: { description: "Vote recorded", content: json(ref("Vote")) },
          ...common,
          409: errorResponse("Already voted"),
        },
      },
    },
    "/jury/results/{caseId}": {
      get: {
        tags: ["Jury"],
        operationId: "getResults",
        summary: "Vote tally and verdict (juror / judge)",
        security: bearer,
        parameters: [idParam("caseId", "Case ID")],
        responses: { 200: { description: "Results", content: json(ref("Results")) }, ...common },
      },
    },
    "/uploads/{filename}": {
      get: {
        tags: ["Uploads"],
        operationId: "downloadEvidence",
        summary: "Download an evidence file (signed-in users)",
        security: bearer,
        parameters: [{ name: "filename", in: "path", required: true, schema: { type: "string" } }],
        responses: { 200: { description: "The file" }, 401: common[401], 404: common[404] },
      },
    },
  },
};
