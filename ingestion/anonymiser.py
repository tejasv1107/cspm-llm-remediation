"""Anonymise findings before they are stored, shared or used for training.

* Account IDs are replaced by a salted SHA-256 hash.
* ARNs are rewritten with a *synthetic but stable* account number and resource name, so
  the ARN keeps its shape (partition/service/region) and the same input always maps to
  the same output, preserving joins across findings.
* Stray 12-digit account numbers in free text are replaced too.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import replace

from ingestion.schema import FindingRecord

ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws[a-z-]*):(?P<service>[a-z0-9-]+):(?P<region>[a-z0-9-]*):"
    r"(?P<account>\d{12}|):(?P<resource>[^\s\"',;]+)"
)
ACCOUNT_ID_PATTERN = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _digest(value: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()


def default_salt() -> str:
    return os.getenv("ANONYMISER_SALT", "change-me")


def hash_account_id(account_id: str, salt: str | None = None) -> str:
    """Salted SHA-256 of an account ID, truncated to 16 hex chars (stable pseudonym)."""
    return _digest(account_id, salt if salt is not None else default_salt())[:16]


def synthetic_account_id(account_id: str, salt: str | None = None) -> str:
    """A stable, fake 12-digit account number derived from the hash (keeps ARN shape)."""
    digest = _digest(account_id, salt if salt is not None else default_salt())
    return f"{int(digest, 16) % 10**12:012d}"


# Only these leading segments are AWS resource *types*; anything else (e.g. an S3 bucket
# name in ``bucket/key``) is customer-chosen and must be hashed, not preserved.
_KNOWN_RESOURCE_TYPES = {
    "instance", "volume", "snapshot", "security-group", "vpc", "subnet", "role", "user",
    "group", "policy", "table", "function", "key", "alias", "trail", "loadbalancer",
    "db", "cluster", "topic", "queue", "secret", "log-group", "certificate",
}


def _synthetic_resource(resource: str, salt: str) -> str:
    """Keep a known resource *type* prefix (``instance/``, ``role/``), hash the rest."""
    match = re.match(r"^([a-z0-9-]+)([/:])(.+)$", resource)
    if match and match.group(1) in _KNOWN_RESOURCE_TYPES:
        prefix, name = match.group(1) + match.group(2), match.group(3)
    else:
        prefix, name = "", resource
    return f"{prefix}res-{_digest(name, salt)[:10]}"


def anonymise_arn(arn: str, salt: str | None = None) -> str:
    """Replace the account ID and resource name inside every ARN found in ``arn``."""
    salt = salt if salt is not None else default_salt()

    def _sub(m: re.Match[str]) -> str:
        account = m.group("account")
        new_account = synthetic_account_id(account, salt) if account else ""
        return (
            f"arn:{m.group('partition')}:{m.group('service')}:{m.group('region')}:"
            f"{new_account}:{_synthetic_resource(m.group('resource'), salt)}"
        )

    return ARN_PATTERN.sub(_sub, arn)


def anonymise_text(text: str, salt: str | None = None) -> str:
    """Anonymise ARNs, then any leftover bare 12-digit account IDs, in free text."""
    salt = salt if salt is not None else default_salt()
    text = anonymise_arn(text, salt)
    return ACCOUNT_ID_PATTERN.sub(lambda m: synthetic_account_id(m.group(0), salt), text)


def anonymise_record(
    record: FindingRecord, salt: str | None = None, *, anonymise_resource: bool = True
) -> FindingRecord:
    """Return a copy of ``record`` with identifying values pseudonymised.

    ``anonymise_resource=False`` keeps ``resource_arn`` (and any ARN/account-id mentions in
    ``title``/``recommendation_text``) untouched while still pseudonymising ``account_id`` and
    ``client_id`` for tenant isolation. Needed for the live remediation pipeline: the generated
    Terraform has to reference the finding's *real* resource to be mergeable, but the account-id
    hash that namespaces PR branches/paths per tenant is unaffected either way. Classifier
    training / dissertation-evaluation data should keep the default (fully anonymised).
    """
    salt = salt if salt is not None else default_salt()
    pseudonym = hash_account_id(record.account_id, salt)
    if anonymise_resource:
        title, resource_arn, recommendation_text = (
            anonymise_text(record.title, salt),
            anonymise_arn(record.resource_arn, salt),
            anonymise_text(record.recommendation_text, salt),
        )
    else:
        title, resource_arn, recommendation_text = (
            record.title, record.resource_arn, record.recommendation_text,
        )
    return replace(
        record,
        finding_id=f"finding-{_digest(record.finding_id, salt)[:16]}",
        account_id=pseudonym,
        client_id=pseudonym,
        title=title,
        resource_arn=resource_arn,
        recommendation_text=recommendation_text,
    )


if __name__ == "__main__":  # pragma: no cover
    sample = "arn:aws:s3:::acme-payroll-bucket"
    print(anonymise_arn("arn:aws:ec2:ap-south-1:123456789012:instance/i-0abc123"))
    print(anonymise_arn(sample))
    print(hash_account_id("123456789012"))
