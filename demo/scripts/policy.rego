package casbin

default deny := []

# Deny if any rule contains "*" in any field (subject/object/action/etc.)
deny[msg] {
  some i
  rule := input.casbin.rules[i]

  some j
  field := rule.fields[j]
  field == "*"

  msg := sprintf("Wildcard '*' is not allowed (ptype=%v fields=%v)", [rule.ptype, rule.fields])
}

# Optional: only enforce on "p" policy lines, not "g" grouping lines
# deny[msg] {
#   some i
#   rule := input.casbin.rules[i]
#   rule.ptype == "p"
#   some j
#   rule.fields[j] == "*"
#   msg := sprintf("Wildcard '*' is not allowed in authorization rules: %v", [rule.fields])
# }
