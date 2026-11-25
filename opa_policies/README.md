# OPA policies

Guard-rails that every LLM-generated Terraform file must pass before a pull request is opened.
They are the last stage of the validation pipeline
(`terraform validate` -> `tflint` -> **OPA**) in [`rag_pipeline/validator.py`](../rag_pipeline/validator.py).

## `terraform_safety.rego`

| # | Rule | What is denied |
|---|------|----------------|
| 1 | No world-open ingress | `0.0.0.0/0` or `::/0` in `aws_security_group` ingress blocks, `aws_security_group_rule` (type `ingress`), `aws_vpc_security_group_ingress_rule`, and allow-ingress `aws_network_acl_rule`. Egress rules are not flagged. |
| 2 | No wildcard IAM | `Allow` statements with `Action = "*"`; service-wide wildcards (`s3:*`) on `Resource = "*"`; inline/`jsonencode` policies with `Action = "*"`; attaching `AdministratorAccess`. `Deny` statements (e.g. deny insecure transport with `s3:*`) are allowed. |
| 3 | No `force_destroy` | Any resource with `force_destroy = true`. |

### Input format

The policy does not read raw HCL. `hcl_to_opa_input()` parses the file with `python-hcl2`, strips the
literal quotes/`__is_block__` markers that library adds, and produces:

```json
{
  "resources": [{"type": "aws_s3_bucket", "name": "logs", "config": {"force_destroy": true}}],
  "data":      [{"type": "aws_iam_policy_document", "name": "p", "config": {"statement": []}}]
}
```

### Run it by hand

```bash
python -c "import json,sys; from rag_pipeline.validator import hcl_to_opa_input; print(json.dumps(hcl_to_opa_input(open(sys.argv[1]).read())))" main.tf \
  | opa eval --format json --stdin-input --data opa_policies/ "data.terraform.safety.deny"
```

An empty `deny` array means the file passed.

### Known limitations

The policy inspects literal values. A CIDR or action passed through a variable
(`cidr_blocks = var.cidrs`) or built by an expression is opaque to it. The prompt builder tells the
model to use literal values for security-relevant attributes, and the human PR review is the backstop.
