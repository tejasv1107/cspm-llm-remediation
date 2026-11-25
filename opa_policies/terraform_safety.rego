# Safety guard-rails applied to every LLM-generated Terraform file before a PR is opened.
#
# Input: the normalised HCL document produced by rag_pipeline/validator.py::hcl_to_opa_input
#
#   {
#     "resources": [{"type": "aws_s3_bucket", "name": "logs", "config": {...}}, ...],
#     "data":      [{"type": "aws_iam_policy_document", "name": "p", "config": {...}}, ...]
#   }
#
# Evaluate with:
#   opa eval --format json --stdin-input --data opa_policies/ "data.terraform.safety.deny"
#
# An empty `deny` set means the file passed. Each message names the offending resource.
package terraform.safety

import rego.v1

open_cidrs := {"0.0.0.0/0", "::/0"}

# Normalise "one block" and "list of blocks" to a list.
as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

# ---------------------------------------------------------------------------
# Rule 1: no world-open (0.0.0.0/0 or ::/0) INGRESS
# ---------------------------------------------------------------------------

# Inline ingress blocks on aws_security_group
deny contains msg if {
	some r in input.resources
	r.type == "aws_security_group"
	some ingress in as_list(object.get(r.config, "ingress", []))
	some cidr in array.concat(
		as_list(object.get(ingress, "cidr_blocks", [])),
		as_list(object.get(ingress, "ipv6_cidr_blocks", [])),
	)
	cidr in open_cidrs
	msg := sprintf("%s.%s: ingress open to %s (0.0.0.0/0 and ::/0 are forbidden)", [r.type, r.name, cidr])
}

# aws_security_group_rule with type = "ingress"
deny contains msg if {
	some r in input.resources
	r.type == "aws_security_group_rule"
	r.config.type == "ingress"
	some cidr in array.concat(
		as_list(object.get(r.config, "cidr_blocks", [])),
		as_list(object.get(r.config, "ipv6_cidr_blocks", [])),
	)
	cidr in open_cidrs
	msg := sprintf("%s.%s: ingress open to %s (0.0.0.0/0 and ::/0 are forbidden)", [r.type, r.name, cidr])
}

# aws_vpc_security_group_ingress_rule (provider >= 5.x)
deny contains msg if {
	some r in input.resources
	r.type == "aws_vpc_security_group_ingress_rule"
	some attr in ["cidr_ipv4", "cidr_ipv6"]
	object.get(r.config, attr, "") in open_cidrs
	msg := sprintf("%s.%s: %s is open to the world (0.0.0.0/0 and ::/0 are forbidden)", [r.type, r.name, attr])
}

# Network ACL rules that allow ingress from anywhere
deny contains msg if {
	some r in input.resources
	r.type == "aws_network_acl_rule"
	object.get(r.config, "egress", false) in [false, "false"]
	object.get(r.config, "rule_action", "") == "allow"
	some attr in ["cidr_block", "ipv6_cidr_block"]
	object.get(r.config, attr, "") in open_cidrs
	msg := sprintf("%s.%s: NACL allows ingress from %s", [r.type, r.name, r.config[attr]])
}

# ---------------------------------------------------------------------------
# Rule 2: no wildcard IAM
# ---------------------------------------------------------------------------

allows(statement) if object.get(statement, "effect", "Allow") == "Allow"

wildcard_action(a) if a in ["*", "*:*"]

service_wildcard(a) if {
	endswith(a, ":*")
	not wildcard_action(a)
}

# aws_iam_policy_document data source: Allow with Action "*"
deny contains msg if {
	some d in input.data
	d.type == "aws_iam_policy_document"
	some statement in as_list(object.get(d.config, "statement", []))
	allows(statement)
	some action in as_list(object.get(statement, "actions", []))
	wildcard_action(action)
	msg := sprintf("data.%s.%s: Allow statement with wildcard action %q", [d.type, d.name, action])
}

# aws_iam_policy_document data source: Allow with service-wide wildcard on Resource "*"
deny contains msg if {
	some d in input.data
	d.type == "aws_iam_policy_document"
	some statement in as_list(object.get(d.config, "statement", []))
	allows(statement)
	"*" in as_list(object.get(statement, "resources", []))
	some action in as_list(object.get(statement, "actions", []))
	service_wildcard(action)
	msg := sprintf("data.%s.%s: Allow %q on Resource \"*\"", [d.type, d.name, action])
}

# Inline JSON / jsonencode() policy documents: Action = "*" (unless the text also has a Deny)
inline_policy_attrs := {"policy", "inline_policy"}

deny contains msg if {
	some r in input.resources
	startswith(r.type, "aws_iam_")
	some attr in inline_policy_attrs
	doc := sprintf("%v", [object.get(r.config, attr, "")])
	regex.match(`Action"?\s*[:=]\s*\[?\s*"(\*|\*:\*)"`, doc)
	not contains(doc, "Deny")
	msg := sprintf("%s.%s: inline policy grants wildcard Action \"*\"", [r.type, r.name])
}

# Attaching the AWS-managed full-admin policy is a wildcard grant in disguise
deny contains msg if {
	some r in input.resources
	startswith(r.type, "aws_iam_")
	arn := object.get(r.config, "policy_arn", "")
	endswith(arn, "/AdministratorAccess")
	msg := sprintf("%s.%s: attaches AdministratorAccess (wildcard IAM)", [r.type, r.name])
}

# ---------------------------------------------------------------------------
# Rule 3: no force_destroy
# ---------------------------------------------------------------------------

deny contains msg if {
	some r in input.resources
	object.get(r.config, "force_destroy", false) in [true, "true"]
	msg := sprintf("%s.%s: force_destroy = true would let Terraform delete non-empty resources", [r.type, r.name])
}
