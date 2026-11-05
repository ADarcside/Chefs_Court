# Chef's Court ⚖️🍳

[![CI](https://github.com/ADarcside/chefs_court/actions/workflows/ci.yml/badge.svg)](https://github.com/ADarcside/chefs_court/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

A REST API for settling kitchen disputes. **Plaintiffs** and **defendants** file cases with
evidence, a **judge** approves them for trial, **jurors** vote, and the judge closes the case
with a final verdict.

Built with Express, MongoDB (Mongoose) and JWT authentication. Interactive docs come with it.

![Demo: judge signs in, searches cases, checks the jury tally and closes the case with a verdict](docs/demo.gif)

<sub>30-second walkthrough in Swagger UI ([MP4](docs/demo.mp4)). Re-record it any time from the **Record demo** GitHub Action.</sub>

## Features

- **Role-based access**: `PLAINTIFF`, `DEFENDANT`, `JUROR`, `JUDGE`
- **Case lifecycle**: `PENDING → APPROVED → CLOSED` (or `REJECTED`)
- **Evidence uploads**: up to 5 files per case (PDF, PNG, JPEG, TXT, max 10 MB each), served only to signed-in users
- **Jury voting**: one final vote per juror per case, with a live tally
- **Verdicts**: the judge closes voting, and the verdict defaults to the jury majority. The judge breaks ties and can override, and an override is recorded.
- **Pagination, filtering and search** on case listings
- **OpenAPI / Swagger UI** at `/docs`
- **Hardened by default**: Helmet, rate limiting (stricter on auth), input validation, judge signup by invite code, regex-safe search
- **Docker Compose** setup, ESLint + Prettier, and an integration test suite run in CI

## Quick start

### With Docker (recommended)

```bash
cp .env.example .env        # set JWT_SECRET and JUDGE_INVITE_CODE
docker compose up --build
```

The API runs at <http://localhost:4000> and the docs at <http://localhost:4000/docs>.

### Locally

Requires Node.js 20+ and a running MongoDB.

```bash
npm install
cp .env.example .env        # edit values
npm run dev                 # auto-restarts on changes
```

## Configuration

| Variable            | Required | Default     | Description                                                      |
| ------------------- | -------- | ----------- | ---------------------------------------------------------------- |
| `MONGO_URI`         | yes      | —           | MongoDB connection string                                        |
| `JWT_SECRET`        | yes      | —           | Secret used to sign tokens. Use a long random value              |
| `JWT_EXPIRES_IN`    | no       | `7d`        | Token lifetime                                                   |
| `JUDGE_INVITE_CODE` | no       | _(empty)_   | Code required to sign up as `JUDGE`. Empty disables judge signup |
| `PORT`              | no       | `4000`      | HTTP port                                                        |
| `UPLOAD_DIR`        | no       | `./uploads` | Where evidence files are stored                                  |
| `CORS_ORIGIN`       | no       | `*`         | Comma-separated allowed origins                                  |

## API overview

Full request/response schemas are in Swagger UI at `/docs` (raw spec: `/openapi.json`).

| Method   | Endpoint                | Who                 | Description                                        |
| -------- | ----------------------- | ------------------- | -------------------------------------------------- |
| `GET`    | `/health`               | anyone              | Liveness check                                     |
| `POST`   | `/auth/signup`          | anyone              | Create an account (`inviteCode` needed for judges) |
| `POST`   | `/auth/login`           | anyone              | Get a JWT                                          |
| `POST`   | `/case/submit`          | plaintiff/defendant | File a case (multipart, optional `files`)          |
| `GET`    | `/case/all`             | any role            | List cases: `?page`, `?limit`, `?status`, `?q`     |
| `GET`    | `/case/:id`             | any role            | Get one case                                       |
| `GET`    | `/case/by-name/:name`   | juror               | Approved cases matching a party name               |
| `PATCH`  | `/case/edit/:id`        | judge               | Edit case fields                                   |
| `PATCH`  | `/case/approve/:id`     | judge               | Open a case for voting                             |
| `PATCH`  | `/case/reject/:id`      | judge               | Reject a case                                      |
| `PATCH`  | `/case/close/:id`       | judge               | Close voting and record the verdict                |
| `DELETE` | `/case/delete/:id`      | judge               | Delete a case with its votes and files             |
| `POST`   | `/jury/vote/:caseId`    | juror               | Vote `guilty` / `not_guilty` (once)                |
| `GET`    | `/jury/results/:caseId` | juror/judge         | Vote tally and verdict                             |
| `GET`    | `/uploads/:filename`    | any role            | Download an evidence file                          |

Jurors only ever see `APPROVED` and `CLOSED` cases.

### Example flow

```bash
API=http://localhost:4000

# 1. Sign up a defendant, a judge and a juror
DEF=$(curl -s -X POST $API/auth/signup -H "Content-Type: application/json" \
  -d '{"name":"Chef Luigi","email":"luigi@example.com","password":"Passw0rd!","role":"DEFENDANT"}' | jq -r .token)
JUDGE=$(curl -s -X POST $API/auth/signup -H "Content-Type: application/json" \
  -d '{"name":"Judge Judy","email":"judy@example.com","password":"Passw0rd!","role":"JUDGE","inviteCode":"<your code>"}' | jq -r .token)
JUROR=$(curl -s -X POST $API/auth/signup -H "Content-Type: application/json" \
  -d '{"name":"Jury Jane","email":"jane@example.com","password":"Passw0rd!","role":"JUROR"}' | jq -r .token)

# 2. File a case
CASE=$(curl -s -X POST $API/case/submit -H "Authorization: Bearer $DEF" \
  -F title="Stolen Pie" -F partyName="Chef Luigi" \
  -F argumentText="I did not steal the pie." -F evidenceText="Timestamped alibi." | jq -r ._id)

# 3. Judge approves, juror votes, judge closes
curl -s -X PATCH $API/case/approve/$CASE -H "Authorization: Bearer $JUDGE"
curl -s -X POST  $API/jury/vote/$CASE -H "Authorization: Bearer $JUROR" \
  -H "Content-Type: application/json" -d '{"choice":"not_guilty"}'
curl -s -X PATCH $API/case/close/$CASE -H "Authorization: Bearer $JUDGE"

# 4. See the verdict
curl -s $API/jury/results/$CASE -H "Authorization: Bearer $JUROR"
```

## Project structure

```
src/
├── app.js               # Express app (middleware, routes, docs)
├── server.js            # Entry point: DB connection, startup, graceful shutdown
├── constants.js         # Roles, statuses, limits
├── config/              # Environment and database
├── docs/openapi.js      # OpenAPI 3 spec
├── middleware/          # Auth, uploads, ObjectId validation, error handling
├── models/              # User, Case, Vote
├── routes/              # auth, case, jury, uploads
├── services/            # Vote tallying
└── utils/               # HTTP helpers, query parsing
test/                    # Integration tests (node:test + supertest + in-memory MongoDB)
```

## Development

```bash
npm test              # run the test suite (downloads an in-memory MongoDB on first run)
npm run lint          # ESLint
npm run format        # Prettier
```

## License

[MIT](LICENSE)
