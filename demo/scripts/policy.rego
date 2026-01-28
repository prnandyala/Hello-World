package casbin

# Rego v1 syntax

deny contains msg if {
  some i
  rule := input.casbin.rules[i]

  some j
  field := rule.fields[j]
  field == "*"

  msg := sprintf("Wildcard '*' is not allowed (ptype=%v fields=%v)", [rule.ptype, rule.fields])
}
