# Signup (juror)
curl -sX POST http://localhost:4000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Jury Jane","email":"jury@example.com","password":"Passw0rd!","role":"JUROR"}'

# Login
TOKEN=$(curl -sX POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jury@example.com","password":"Passw0rd!"}' | jq -r .token)

# Submit a case (as defendant)
# First create a defendant user, login, then:
curl -sX POST http://localhost:4000/case/submit \
  -H "Authorization: Bearer $DEF_TOKEN" \
  -F title="Stolen Pie" \
  -F partyName="Chef Luigi" \
  -F argumentText="I did not steal the pie." \
  -F evidenceText="Timestamped alibi." \
  -F files=@/path/to/optional_doc.pdf

# Approve as judge
curl -sX PATCH http://localhost:4000/case/approve/<CASE_ID> \
  -H "Authorization: Bearer $JUDGE_TOKEN"

# Juror get approved cases
curl -s http://localhost:4000/case/all \
  -H "Authorization: Bearer $TOKEN"

# Juror votes
curl -sX POST http://localhost:4000/jury/vote/<CASE_ID> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"choice":"guilty"}'

# Results
curl -s http://localhost:4000/jury/results/<CASE_ID> \
  -H "Authorization: Bearer $TOKEN"
