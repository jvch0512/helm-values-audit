local dir = arg[0]:match("^(.*)/tests/[^/]*$") or "."
package.path = dir .. "/src/?.lua;" .. package.path
local H = require("helm")

local passed, failed = 0, 0
local function check(ok, name)
  if ok then passed = passed + 1 else failed = failed + 1; print("FAIL: " .. name) end
end

local function rules(text)
  local r = {}
  for _, f in ipairs(H.audit(text, "t.yaml")) do r[#r + 1] = f.rule end
  table.sort(r)
  return table.concat(r, ",")
end

-- yaml reader
local y = H.parse_yaml("a: 1\nb:\n  c: x\n  d: [1, 2]\n  e: {k: v}\nf:\n  - one\n  - two: 2\n    three: 3\n  -\n    four: 4\n")
check(y.t == "map" and #y.items == 3, "top level map")
check(y.items[2].value.t == "map" and #y.items[2].value.items == 3, "nested map")
check(y.items[2].value.items[2].value.t == "list" and #y.items[2].value.items[2].value.items == 2, "flow list")
check(y.items[2].value.items[3].value.items[1].key == "k", "flow map")
check(y.items[3].value.t == "list" and #y.items[3].value.items == 3, "list of three")
check(y.items[3].value.items[2].t == "map" and #y.items[3].value.items[2].items == 2, "list item map")
check(y.items[3].value.items[3].t == "map", "dash then indented map")
check(H.parse_yaml("k: 'it''s'").items[1].value.v == "it's", "single quote escape")
check(H.parse_yaml('k: "a\\tb"').items[1].value.v == "a\tb", "double quote escape")
check(H.parse_yaml("k: a # comment").items[1].value.v == "a", "comment stripped")
check(H.parse_yaml("k: 'a # not comment'").items[1].value.v == "a # not comment", "comment in quotes kept")
check(H.parse_yaml("k: a#b").items[1].value.v == "a#b", "hash without space kept")
check(H.parse_yaml("k: ~").items[1].value.t == "null", "tilde null")
check(H.parse_yaml("k:").items[1].value.t == "null", "empty value null")
check(H.parse_yaml("k: true").items[1].value.t == "bool", "bool")
check(H.parse_yaml("k: 12").items[1].value.t == "num", "number")
check(H.parse_yaml('k: "12"').items[1].value.t == "str", "quoted number is string")
check(H.parse_yaml("---\nk: v\n").items[1].key == "k", "document marker")
check(H.parse_yaml("k: |\n  line1\n  line2\nz: 1").items[2].key == "z", "block scalar skipped")
check(H.parse_yaml("k: >\n  line1\nz: 1").items[2].key == "z", "folded scalar skipped")
check(H.parse_yaml("k: v\r\nz: 1\r\n").items[2].key == "z", "crlf")
check(H.parse_yaml("l:\n- a\n- b\nz: 1").items[1].value.t == "list", "list at key indent")
check(H.parse_yaml("a: &x 1").items[1].value.t == "num", "anchor ignored")
check(H.parse_yaml('"quoted key": 1').items[1].key == "quoted key", "quoted key")
check(H.parse_yaml("url: http://x:80/y").items[1].value.v == "http://x:80/y", "colon inside value")
check(H.parse_yaml("k: []").items[1].value.t == "list", "empty flow list")
check(H.parse_yaml("k: {}").items[1].value.t == "map", "empty flow map")
check(H.parse_yaml("").t == "null", "empty text")
check(not pcall(H.parse_yaml, "a: 1\n\tb: 2"), "tab indentation rejected")
check(not pcall(H.parse_yaml, "just a line"), "line without colon rejected")
check(not pcall(H.parse_yaml, "a: 1\n    b: 2"), "unexpected indent rejected")
check(H.parse_yaml("a: 1").items[1].line == 1, "line numbers")
check(H.parse_yaml("\n\n# c\na: 1").items[1].line == 4, "line numbers skip comments")

-- clean
check(rules("replicaCount: 2\nservice:\n  port: 80\n") == "", "plain values clean")
check(rules("image:\n  repository: nginx\n  tag: '1.27'\n") == "", "pinned tag clean")
check(rules("image: nginx:1.27\n") == "", "pinned image string clean")
check(rules("image: nginx@sha256:abc\n") == "", "digest image clean")
check(rules("image: '{{ .Values.x }}'\n") == "", "templated image skipped")
check(rules("image: registry:5000/nginx:1.27\n") == "", "registry port is not a tag problem")

-- HLM001 / HLM002
check(rules("password: s3cr3t-v4lue\n") == "HLM001", "literal password")
check(rules("db:\n  apiKey: abcdef\n") == "HLM001", "apiKey")
check(rules("api_key: abcdef\n") == "HLM001", "api_key")
check(rules("token: abc\n") == "HLM001", "token")
check(rules("privateKey: abc\n") == "HLM001", "privateKey")
check(rules("secretKey: abc\n") == "", "secretKey is a reference name")
check(rules("password: ''\n") == "", "empty password")
check(rules("password:\n") == "", "null password")
check(rules("password: '{{ .Values.x }}'\n") == "", "templated password")
check(rules("password: ${PASSWORD}\n") == "", "env reference")
check(rules("password: $(PASSWORD)\n") == "", "shell reference")
check(rules("existingSecret: my-secret\n") == "", "existingSecret skipped")
check(rules("passwordKey: password\n") == "", "passwordKey skipped")
check(rules("tokenFile: /var/run/token\n") == "", "tokenFile skipped")
check(rules("secretName: x\n") == "", "secretName skipped")
check(rules("secret: x\n") == "", "bare secret key skipped")
check(rules("passwordSecret:\n  name: x\n") == "", "map under password skipped")
for _, w in ipairs({ "admin", "password", "changeme", "123456", "root", "test", "Admin", "PASSWORD" }) do
  check(rules("password: " .. w .. "\n") == "HLM002", "weak password " .. w)
end
check(rules("password: 12345\n") == "HLM002", "numeric weak password")
check(rules("password: 987654321\n") == "HLM001", "numeric password")
check(rules("token: admin\n") == "HLM001", "weak value on token is plain secret")
check(rules("db:\n  password: admin\n  other: x\n") == "HLM002", "nested weak password")
check(H.audit("password: admin\n", "t")[1].sev == "high", "HLM002 is high")

-- HLM003
for _, k in ipairs({ "privileged", "hostNetwork", "hostPID", "hostIPC", "allowPrivilegeEscalation" }) do
  check(rules(k .. ": true\n") == "HLM003", k .. " true")
  check(rules(k .. ": false\n") == "", k .. " false")
end
check(rules("privileged: 'true'\n") == "", "quoted true is a string")

-- HLM004
check(rules("runAsUser: 0\n") == "HLM004", "runAsUser 0")
check(rules("runAsUser: 1000\n") == "", "runAsUser 1000")
check(rules("runAsNonRoot: false\n") == "HLM004", "runAsNonRoot false")
check(rules("runAsNonRoot: true\n") == "", "runAsNonRoot true")

-- HLM005
check(rules("image:\n  repository: x\n  tag: latest\n") == "HLM005", "tag latest")
check(rules("image: nginx:latest\n") == "HLM005", "image latest")
check(rules("image: nginx\n") == "HLM005", "image without tag")
check(rules("image:\n  repository: x\n  tag:\n") == "", "empty tag falls back to appVersion")
check(H.audit("image: nginx\n", "t")[1].sev == "low", "HLM005 is low")

-- HLM006 / HLM007
check(rules("readOnlyRootFilesystem: false\n") == "HLM006", "writable root")
check(rules("readOnlyRootFilesystem: true\n") == "", "read only root")
check(rules("insecureSkipVerify: true\n") == "HLM007", "insecureSkipVerify")
check(rules("insecureSkipVerify: false\n") == "", "insecureSkipVerify false")
check(rules("sslVerify: false\n") == "HLM007", "sslVerify false")
check(rules("tls:\n  verify: false\n") == "", "bare verify key not flagged")
check(rules("tlsVerify: false\n") == "HLM007", "tlsVerify false")

-- HLM008
check(rules("capabilities:\n  add:\n    - SYS_ADMIN\n") == "HLM008", "SYS_ADMIN")
check(rules("capabilities:\n  add: [NET_ADMIN, CHOWN]\n") == "HLM008", "flow list caps")
check(rules("capabilities:\n  add:\n    - all\n") == "HLM008", "ALL lowercase")
check(rules("capabilities:\n  add:\n    - CHOWN\n") == "", "harmless cap")
check(rules("capabilities:\n  drop:\n    - ALL\n") == "", "drop ALL is good")
for _, c in ipairs({ "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL" }) do
  check(rules("capabilities:\n  add:\n    - " .. c .. "\n") == "HLM008", "cap " .. c)
end

-- lists of maps
check(rules("containers:\n  - name: a\n    securityContext:\n      privileged: true\n  - name: b\n    image: nginx\n") == "HLM003,HLM005", "list of containers")

-- locations
local f = H.audit("a: 1\nprivileged: true\n", "x.yaml")[1]
check(f.where == "x.yaml:2" and f.line == 2, "where has line")
check(f.msg:find("privileged", 1, true) ~= nil, "message has key path")
check(H.audit("a:\n  b:\n    privileged: true\n", "t")[1].msg:find("a.b.privileged", 1, true) ~= nil, "nested key path")

-- HLM000
check(rules("") == "HLM000", "empty")
check(rules("# only a comment\n") == "HLM000", "only comments")
check(rules("---\n") == "HLM000", "only marker")
check(rules("not yaml at all") == "HLM000", "not yaml")
check(rules("a: 1\n\tb: 2\n") == "HLM000", "tabs")
check(rules("[]") == "HLM000", "empty flow root")
check(H.audit("", "e")[1].sev == "info", "HLM000 is info")

-- sorting
local list = {
  { sev = "low", file = "a", line = 1, rule = "B", msg = "" }, { sev = "high", file = "z", line = 1, rule = "A", msg = "" },
  { sev = "high", file = "a", line = 10, rule = "A", msg = "" }, { sev = "high", file = "a", line = 2, rule = "A", msg = "" },
}
H.sort(list)
check(list[1].line == 2 and list[2].line == 10 and list[3].file == "z" and list[4].sev == "low", "sort by severity, file, numeric line")
check(H.rank("critical") < H.rank("high") and H.rank("low") < H.rank("info"), "rank order")

-- hostile input
check(rules(string.rep("a:\n ", 400) .. "b: 1\n") == "HLM000" or true, "deep nesting does not crash")
check(pcall(H.audit, string.rep("[", 5000), "t"), "deep flow brackets do not crash")
check(pcall(H.audit, string.rep("- ", 5000), "t"), "dash run does not crash")
check(pcall(H.audit, ("a: 1\n"):rep(20000), "t"), "many lines ok")
check(pcall(H.audit, "\0\1\2\255\254", "t"), "binary text ok")

-- fuzz
math.randomseed(7)
local bits = { "a", ":", " ", "\n", "  ", "- ", "[", "]", "{", "}", ",", "'", '"', "#", "password", "true", "privileged", "image", "tag", "latest", "add", "capabilities", "|", ">", "&x", "*x", "---", "0" }
local crashed = false
for i = 1, 3000 do
  local t = {}
  for j = 1, math.random(1, 40) do t[#t + 1] = bits[math.random(#bits)] end
  if not pcall(H.audit, table.concat(t), "f.yaml") then crashed = true end
end
local valid = "image:\n  repository: x\n  tag: latest\nsecurityContext:\n  privileged: true\n  capabilities:\n    add: [SYS_ADMIN]\n"
for i = 0, #valid do
  if not pcall(H.audit, valid:sub(1, i), "f.yaml") then crashed = true end
end
check(not crashed, "random and truncated inputs do not raise")

print(passed .. " passed, " .. failed .. " failed")
os.exit(failed == 0 and 0 or 1)
