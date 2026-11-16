# shellcheck shell=bash
# ******************************************************************************
# *Title: Awk JSON Library*
# *Author: Kyle Versluis (@ktalons)*
# *Description: Reads typed fields from line-delimited JSON records in awk.*
# ******************************************************************************

# *--- Record Parsing ---*

# Parse a single object into typed nodes. Each lookup selects a direct child.
# Duplicate keys, malformed values and excessive nesting reject the record.
# shellcheck disable=SC2034  # consumed by structured format analyzers
AWK_JSON_LIB='
function bl_json(line,    key, root) {
  for (key in J_child) delete J_child[key]
  for (key in J_type) delete J_type[key]
  for (key in J_value) delete J_value[key]
  J_line = line
  J_pos = 1
  J_nodes = 0
  root = bl_jparse(0)
  bl_jspace()
  return J_type[root] == "{" && J_pos > length(J_line) ? root : 0
}

function bl_jspace() {
  while (substr(J_line, J_pos, 1) ~ /^[ \t\r\n]$/) J_pos++
}

function bl_jparse(depth,    node, c, close_char, key, child, n, t) {
  if (depth > 32) return 0
  bl_jspace()
  node = ++J_nodes
  c = substr(J_line, J_pos, 1)
  if (c == "{" || c == "[") {
    J_type[node] = c
    close_char = c == "{" ? "}" : "]"
    J_pos++
    bl_jspace()
    if (substr(J_line, J_pos, 1) == close_char) { J_pos++; return node }
    while (1) {
      if (c == "{") {
        if (substr(J_line, J_pos, 1) != "\"" || !bl_jread_string()) return 0
        key = J_string
        bl_jspace()
        if (substr(J_line, J_pos++, 1) != ":") return 0
      } else key = ++n
      if ((node SUBSEP key) in J_child) return 0
      child = bl_jparse(depth + 1)
      if (!child) return 0
      J_child[node, key] = child
      bl_jspace()
      t = substr(J_line, J_pos++, 1)
      if (t == close_char) return node
      if (t != ",") return 0
      bl_jspace()
    }
  }
  if (c == "\"") {
    if (!bl_jread_string()) return 0
    J_type[node] = "string"
    J_value[node] = J_string
    return node
  }

  t = substr(J_line, J_pos)
  if (!match(t, /^(true|false|null|-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?)/)) return 0
  J_type[node] = c ~ /^[-0-9]$/ ? "number" : "literal"
  J_value[node] = substr(t, 1, RLENGTH)
  J_pos += RLENGTH
  return node
}

# *--- Strings and Field Access ---*

function bl_jread_string(    c, cp, low, start) {
  J_string = ""
  J_pos++
  start = J_pos
  while (J_pos <= length(J_line)) {
    c = substr(J_line, J_pos++, 1)
    if (c == "\"") {
      J_string = J_string substr(J_line, start, J_pos - start - 1)
      return 1
    }
    # Older Wazuh exports can carry a literal tab in a string. The analyzer
    # folds it to a space before sending the value to Bash.
    if (c < " " && c != "\t") return 0
    if (c != "\\") continue
    J_string = J_string substr(J_line, start, J_pos - start - 1)
    c = substr(J_line, J_pos++, 1)
    if (c == "u") {
      cp = bl_jhex4()
      if (cp < 0) return 0
      if (cp >= 55296 && cp <= 56319) {
        if (substr(J_line, J_pos, 2) != "\\u") return 0
        J_pos += 2
        low = bl_jhex4()
        if (low < 56320 || low > 57343) return 0
        cp = 65536 + (cp - 55296) * 1024 + low - 56320
      } else if (cp >= 56320 && cp <= 57343) return 0
      # Shell strings cannot carry NUL. Preserve the escape visibly.
      c = cp ? bl_jutf8(cp) : "\\u0000"
    } else if (c == "b") c = "\b"
    else if (c == "f") c = "\f"
    else if (c == "n") c = "\n"
    else if (c == "r") c = "\r"
    else if (c == "t") c = "\t"
    else if (c != "\"" && c != "\\" && c != "/") return 0
    J_string = J_string c
    start = J_pos
  }
  return 0
}

function bl_jhex4(    hex, i, n) {
  hex = tolower(substr(J_line, J_pos, 4))
  if (hex !~ /^[0-9a-f]{4}$/) return -1
  J_pos += 4
  for (i = 1; i <= 4; i++) n = n * 16 + index("0123456789abcdef", substr(hex, i, 1)) - 1
  return n
}

function bl_jutf8(n) {
  if (n < 128) return sprintf("%c", n)
  if (n < 2048) return sprintf("%c%c", 192 + int(n / 64), 128 + n % 64)
  if (n < 65536)
    return sprintf("%c%c%c", 224 + int(n / 4096), 128 + int(n / 64) % 64, 128 + n % 64)
  return sprintf("%c%c%c%c", 240 + int(n / 262144), 128 + int(n / 4096) % 64,
                 128 + int(n / 64) % 64, 128 + n % 64)
}

function bl_jget(node, key, type,    child) {
  if (!((node SUBSEP key) in J_child)) return 0
  child = J_child[node, key]
  return type == "" || J_type[child] == type ? child : 0
}

function bl_jstr(node, key,    child) {
  child = bl_jget(node, key, "string")
  return child ? J_value[child] : ""
}
'
