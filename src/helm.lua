-- helm-values-audit core: a small YAML reader plus the audit rules.
local M = {}

local RANK = { critical = 0, high = 1, medium = 2, low = 3, info = 4 }
function M.rank(sev) return RANK[sev] or 4 end

------------------------------------------------------------------ YAML reader
local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

-- remove a trailing comment that is outside quotes
local function strip_comment(s)
  local q, i, n = nil, 1, #s
  while i <= n do
    local c = s:sub(i, i)
    if q then
      if c == "\\" and q == '"' then i = i + 1
      elseif c == q then q = nil end
    elseif c == '"' or c == "'" then
      if i == 1 or s:sub(i - 1, i - 1):match("[%s:,%[%{%-]") then q = c end
    elseif c == "#" and (i == 1 or s:sub(i - 1, i - 1):match("%s")) then
      return trim(s:sub(1, i - 1))
    end
    i = i + 1
  end
  return trim(s)
end

local function unquote(s)
  local a = s:sub(1, 1)
  if #s >= 2 and a == '"' and s:sub(-1) == '"' then
    return (s:sub(2, -2):gsub('\\(.)', function(c)
      if c == "n" then return "\n" elseif c == "t" then return "\t" end
      return c
    end))
  elseif #s >= 2 and a == "'" and s:sub(-1) == "'" then
    return (s:sub(2, -2):gsub("''", "'"))
  end
  return s
end

local function scalar(raw, line)
  local s = trim(raw)
  local quoted = (s:sub(1, 1) == '"' or s:sub(1, 1) == "'")
  local v = unquote(s)
  if quoted then return { t = "str", v = v, line = line } end
  if v == "" or v == "~" or v == "null" or v == "Null" or v == "NULL" then return { t = "null", line = line } end
  if v == "true" or v == "True" or v == "TRUE" then return { t = "bool", v = true, line = line } end
  if v == "false" or v == "False" or v == "FALSE" then return { t = "bool", v = false, line = line } end
  if v:match("^[-+]?%d+%.?%d*$") then return { t = "num", v = v, line = line } end
  return { t = "str", v = v, line = line }
end

local function split_flow(s)
  local parts, depth, q, cur = {}, 0, nil, {}
  for i = 1, #s do
    local c = s:sub(i, i)
    if q then
      cur[#cur + 1] = c
      if c == q then q = nil end
    elseif c == '"' or c == "'" then q = c; cur[#cur + 1] = c
    elseif c == "[" or c == "{" then depth = depth + 1; cur[#cur + 1] = c
    elseif c == "]" or c == "}" then depth = depth - 1; cur[#cur + 1] = c
    elseif c == "," and depth == 0 then parts[#parts + 1] = table.concat(cur); cur = {}
    else cur[#cur + 1] = c end
  end
  local last = table.concat(cur)
  if trim(last) ~= "" then parts[#parts + 1] = last end
  return parts
end

local function find_colon(s)
  -- first ": " or trailing ":" outside quotes
  local q = nil
  for i = 1, #s do
    local c = s:sub(i, i)
    if q then
      if c == q then q = nil end
    elseif c == '"' or c == "'" then
      if i == 1 then q = c end
    elseif c == ":" and (i == #s or s:sub(i + 1, i + 1):match("%s")) then
      return i
    end
  end
  return nil
end

local flow
local function parse_value(raw, line)
  local s = trim(raw)
  local f = s:sub(1, 1)
  if (f == "[" and s:sub(-1) == "]") or (f == "{" and s:sub(-1) == "}") then
    return flow(s, line)
  end
  return scalar(s, line)
end

flow = function(s, line)
  local inner = trim(s:sub(2, -2))
  if s:sub(1, 1) == "[" then
    local node = { t = "list", items = {}, line = line }
    for _, p in ipairs(split_flow(inner)) do
      node.items[#node.items + 1] = parse_value(p, line)
    end
    return node
  end
  local node = { t = "map", items = {}, line = line }
  for _, p in ipairs(split_flow(inner)) do
    local c = find_colon(trim(p))
    local tp = trim(p)
    if c then
      node.items[#node.items + 1] = { key = unquote(trim(tp:sub(1, c - 1))), value = parse_value(tp:sub(c + 1), line), line = line }
    elseif tp ~= "" then
      node.items[#node.items + 1] = { key = unquote(tp), value = { t = "null", line = line }, line = line }
    end
  end
  return node
end

local MAXLINES = 200000

function M.parse_yaml(text)
  local lines = {}
  local raw = {}
  local n = 0
  for ln in (text .. "\n"):gmatch("(.-)\r?\n") do
    n = n + 1
    if n > MAXLINES then error("too many lines") end
    raw[n] = ln
  end
  for no = 1, n do
    local ln = raw[no]
    local ind = #ln:match("^[ \t]*")
    local body = strip_comment(ln:sub(ind + 1))
    if body ~= "" and not (ind == 0 and (body == "---" or body == "...")) and not body:match("^%%") then
      if ln:sub(1, ind):find("\t") then error("tab indentation at line " .. no) end
      lines[#lines + 1] = { ind = ind, text = body, no = no }
    end
  end
  if #lines == 0 then return { t = "null", line = 1 } end

  local pos = 1
  local parse_block

  local function skip_block_scalar(ind)
    -- lines more indented than the key belong to the block scalar
    while lines[pos] and lines[pos].ind > ind do pos = pos + 1 end
  end

  local function value_after(rest, ind, no, depth)
    -- rest is the text after "key:" (comment-free)
    local r = trim(rest)
    r = r:gsub("^[&!]%S+%s*", "")
    if r == "" then
      local nx = lines[pos]
      if nx and nx.ind > ind then return parse_block(nx.ind, depth + 1) end
      if nx and nx.ind == ind and (nx.text:sub(1, 2) == "- " or nx.text == "-") then
        return parse_block(ind, depth + 1)
      end
      return { t = "null", line = no }
    end
    local c = r:sub(1, 1)
    if c == "|" or c == ">" then
      skip_block_scalar(ind)
      return { t = "str", v = "", line = no, block = true }
    end
    if c == "*" then return { t = "str", v = r, line = no, alias = true } end
    return parse_value(r, no)
  end

  parse_block = function(ind, depth)
    if depth > 100 then error("nesting too deep") end
    local first = lines[pos]
    if not first then return { t = "null", line = 1 } end
    if first.text:sub(1, 2) == "- " or first.text == "-" then
      local node = { t = "list", items = {}, line = first.no }
      while lines[pos] and lines[pos].ind == ind and (lines[pos].text:sub(1, 2) == "- " or lines[pos].text == "-") do
        local ln = lines[pos]
        local content = trim(ln.text:sub(2))
        if content == "" then
          pos = pos + 1
          local nx = lines[pos]
          if nx and nx.ind > ind then
            node.items[#node.items + 1] = parse_block(nx.ind, depth + 1)
          else
            node.items[#node.items + 1] = { t = "null", line = ln.no }
          end
        else
          local off = #ln.text - #ln.text:sub(2):gsub("^%s+", "") + 1 -- column of content within text
          local c = find_colon(content)
          local fc = content:sub(1, 1)
          if c and fc ~= "[" and fc ~= "{" and fc ~= '"' and fc ~= "'" then
            -- "- key: value" starts a map whose indent is the content column
            ln.ind = ind + off - 1
            ln.text = content
            node.items[#node.items + 1] = parse_block(ln.ind, depth + 1)
          else
            pos = pos + 1
            node.items[#node.items + 1] = parse_value(content:gsub("^[&!]%S+%s*", ""), ln.no)
          end
        end
      end
      return node
    end
    local node = { t = "map", items = {}, line = first.no }
    while lines[pos] and lines[pos].ind == ind and not (lines[pos].text:sub(1, 2) == "- " or lines[pos].text == "-") do
      local ln = lines[pos]
      local c = find_colon(ln.text)
      if not c then error("expected key: value at line " .. ln.no) end
      local key = unquote(trim(ln.text:sub(1, c - 1)))
      pos = pos + 1
      local v = value_after(ln.text:sub(c + 1), ind, ln.no, depth)
      node.items[#node.items + 1] = { key = key, value = v, line = ln.no }
    end
    local nx = lines[pos]
    if nx and nx.ind > ind and #node.items > 0 then error("unexpected indentation at line " .. nx.no) end
    return node
  end

  local root = parse_block(lines[1].ind, 0)
  if lines[pos] then error("unexpected content at line " .. lines[pos].no) end
  return root
end

------------------------------------------------------------------ rules
local SECRET_WORDS = { "password", "passwd", "secret", "token", "apikey", "api_key", "privatekey", "private_key", "accesskey", "access_key", "secretkey", "secret_key", "credential" }
local SKIP_WORDS = { "existing", "name", "ref", "enabled", "path", "file", "mount", "annotation", "length", "kind", "key", "keys", "policy", "type", "label", "namespace", "secretkeyref", "from", "env", "selector", "field", "persist", "id-" }
local WEAK = { admin = true, password = true, changeme = true, ["change-me"] = true, ["change_me"] = true, ["123456"] = true, ["12345678"] = true, root = true, secret = true, test = true, default = true, letmein = true, qwerty = true, ["1234"] = true, ["12345"] = true, guest = true, pass = true, ["admin123"] = true, ["password1"] = true, ["p@ssw0rd"] = true }
local NON_SECRET_VALUES = { ["true"] = true, ["false"] = true, yes = true, no = true, null = true, none = true, read = true, write = true }
local BAD_CAPS = { SYS_ADMIN = true, NET_ADMIN = true, SYS_PTRACE = true, SYS_MODULE = true, ALL = true }

local function has_any(s, words)
  for _, w in ipairs(words) do if s:find(w, 1, true) then return true end end
  return false
end

local function secret_key(key)
  local k = key:lower()
  if not has_any(k, SECRET_WORDS) then return false end
  -- reference-like names are skipped, except when the whole word is just the secret word
  local stripped = k
  for _, w in ipairs(SECRET_WORDS) do stripped = stripped:gsub(w, "") end
  if k == "secret" or k == "secrets" then return false end
  for _, w in ipairs(SKIP_WORDS) do
    if stripped:find(w, 1, true) then return false end
  end
  return true
end

local function lastseg(path)
  return (path:match("([^%.%[%]]+)%]?$")) or path
end

local function image_problem(v)
  if v:find("{{", 1, true) then return nil end
  if v:find("@sha256:", 1, true) then return nil end
  local name = v:match("([^/]+)$") or v
  local tag = name:match(":([^:]+)$")
  if not tag then return "has no tag" end
  if tag == "latest" then return "uses the latest tag" end
  return nil
end

function M.audit(text, file)
  local ok, root = pcall(M.parse_yaml, text)
  if not ok then
    return { { sev = "info", rule = "HLM000", file = file, where = file, line = 0, msg = "not YAML this reader understands, ignored" } }
  end
  if root.t == "null" or (root.t == "map" and #root.items == 0) or (root.t == "list" and #root.items == 0) then
    return { { sev = "info", rule = "HLM000", file = file, where = file, line = 0, msg = "empty file, ignored" } }
  end
  local out = {}
  local function add(sev, rule, line, path, msg)
    out[#out + 1] = { sev = sev, rule = rule, file = file, line = line, where = file .. ":" .. line, msg = path .. " " .. msg }
  end

  local function walk(node, path, parent_key)
    if node.t == "map" then
      -- image given as repository + tag
      local repo, tag
      for _, it in ipairs(node.items) do
        if it.key == "repository" and it.value.t == "str" then repo = it end
        if it.key == "tag" then tag = it end
      end
      if repo and tag and tag.value.t ~= "null" then
        local tv = tag.value.v
        if tag.value.t == "str" and tv == "latest" then
          add("low", "HLM005", tag.line, path .. ".tag", "uses the latest tag")
        end
      end
      for _, it in ipairs(node.items) do
        local p = (path == "" and it.key) or (path .. "." .. it.key)
        local v = it.value
        local k = it.key
        local kl = k:lower()
        if v.t == "bool" then
          if v.v == true and (k == "privileged" or k == "hostNetwork" or k == "hostPID" or k == "hostIPC" or k == "allowPrivilegeEscalation") then
            add("high", "HLM003", it.line, p, "is true")
          elseif v.v == false and k == "runAsNonRoot" then
            add("medium", "HLM004", it.line, p, "is false")
          elseif v.v == false and k == "readOnlyRootFilesystem" then
            add("low", "HLM006", it.line, p, "is false")
          elseif v.v == true and (kl == "insecureskipverify" or kl == "skiptlsverify" or kl == "insecure" or kl == "skipverify" or kl == "insecuretls" or kl == "tlsinsecure") then
            add("medium", "HLM007", it.line, p, "disables TLS verification")
          elseif v.v == false and (kl == "sslverify" or kl == "tlsverify" or kl == "verifytls" or kl == "verifyssl" or kl == "verifycertificates") then
            add("medium", "HLM007", it.line, p, "disables TLS verification")
          end
        elseif v.t == "num" and k == "runAsUser" and tonumber(v.v) == 0 then
          add("medium", "HLM004", it.line, p, "is 0 (root)")
        elseif v.t == "str" and not v.block and not v.alias then
          if k == "image" then
            local prob = image_problem(v.v)
            if prob then add("low", "HLM005", it.line, p, prob) end
          end
          if secret_key(k) and v.v ~= "" and not NON_SECRET_VALUES[v.v:lower()] and not v.v:find("{{", 1, true) and not v.v:match("^%$[%({]") then
            if WEAK[v.v:lower()] and has_any(kl, { "password", "passwd" }) then
              add("high", "HLM002", it.line, p, "has the weak default value " .. string.format("%q", v.v))
            else
              add("high", "HLM001", it.line, p, "holds a hard-coded value")
            end
          end
        elseif v.t == "num" and secret_key(k) and has_any(kl, { "password", "passwd" }) then
          if WEAK[tostring(v.v)] then
            add("high", "HLM002", it.line, p, "has the weak default value " .. tostring(v.v))
          else
            add("high", "HLM001", it.line, p, "holds a hard-coded value")
          end
        end
        walk(v, p, k)
      end
    elseif node.t == "list" then
      for i, v in ipairs(node.items) do
        local p = path .. "[" .. (i - 1) .. "]"
        if v.t == "str" and parent_key == "add" and BAD_CAPS[v.v:upper()] then
          add("high", "HLM008", v.line, p, "adds the " .. v.v:upper() .. " capability")
        end
        walk(v, p, parent_key)
      end
    end
  end
  walk(root, "", nil)
  return out
end

function M.sort(findings)
  table.sort(findings, function(a, b)
    local ra, rb = M.rank(a.sev), M.rank(b.sev)
    if ra ~= rb then return ra < rb end
    if a.file ~= b.file then return a.file < b.file end
    if a.line ~= b.line then return a.line < b.line end
    if a.rule ~= b.rule then return a.rule < b.rule end
    return a.msg < b.msg
  end)
  return findings
end

------------------------------------------------------------------ files
local function shq(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

local function is_dir(path)
  return os.execute("test -d " .. shq(path)) == true
end

function M.is_dir(path) return is_dir(path) end

-- When walking a directory only values files are audited: Helm templates are Go templates, not YAML,
-- and workflows or unit tests in a chart repository are not chart values.
function M.is_values_file(rel)
  local r = "/" .. rel:lower()
  if r:find("/templates/", 1, true) or r:find("/%.github/") or r:find("/unittests/", 1, true) or r:find("/ci/", 1, true) then return false end
  local name = r:match("([^/]+)$") or ""
  return name:match("values[^/]*%.ya?ml$") ~= nil
end

function M.list_files(dir)
  local p = io.popen("find " .. shq(dir) .. " -type f \\( -name '*.yaml' -o -name '*.yml' \\) -not -path '*/.git/*' 2>/dev/null")
  if not p then return {} end
  local res = {}
  local base = dir:gsub("/+$", "")
  for l in p:lines() do
    local rel = l:sub(1, #base + 1) == base .. "/" and l:sub(#base + 2) or l
    if M.is_values_file(rel) then res[#res + 1] = { rel = rel, full = l } end
  end
  p:close()
  table.sort(res, function(a, b) return a.rel < b.rel end)
  return res
end

function M.audit_path(path)
  local files
  if is_dir(path) then
    files = M.list_files(path)
  else
    files = { { rel = path:match("([^/]+)$") or path, full = path } }
  end
  local all = {}
  for _, f in ipairs(files) do
    local text = ""
    local fh = io.open(f.full, "rb")
    if fh then
      local size = fh:seek("end")
      fh:seek("set", 0)
      if size and size <= 50000000 then text = fh:read("a") or "" end
      fh:close()
    end
    for _, x in ipairs(M.audit(text, f.rel)) do all[#all + 1] = x end
  end
  return M.sort(all), #files
end

return M
