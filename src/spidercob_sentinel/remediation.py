"""
Remediation knowledge base — plain-text fix guidance per finding type.

Ported from Spidercob's internal remediation engine. This is generic
security advice (parameterized queries, secret rotation steps, etc.), not
proprietary logic — publishing it is a deliberate choice, consistent with
the rest of this project being open source.
"""
from __future__ import annotations

KB = {
    # ── Cloud credentials ──────────────────────────────────────────────
    "aws_access_key":         "Rotate key immediately via AWS IAM console. Store in AWS Secrets Manager or as environment variables — never in source code.",
    "aws_key_id":             "Rotate key immediately via AWS IAM console. Store in AWS Secrets Manager or as environment variables — never in source code.",
    "aws_secret_key":         "Rotate secret immediately via AWS IAM console. Use IAM roles or AWS Secrets Manager instead of static credentials.",
    "aws_session_token":      "Invalidate session token immediately. Use short-lived IAM role credentials via STS AssumeRole instead.",
    "azure_connection_string":"Regenerate the connection string in the Azure portal. Store it in Azure Key Vault and reference via managed identity.",
    "azure_sas_token":        "Revoke the SAS token in the Azure portal. Generate short-lived tokens on demand — do not embed in code or documents.",
    "google_api_key":         "Revoke the key in the Google Cloud Console. Restrict key scope to specific APIs and IPs. Store in Secret Manager.",
    "cloudflare_api_token":   "Revoke the token in the Cloudflare dashboard. Use scoped tokens with minimal permissions and store in a vault.",

    # ── Source control & CI tokens ─────────────────────────────────────
    "github_token":           "Revoke the token immediately on github.com/settings/tokens. Use short-lived GitHub Actions OIDC tokens instead of PATs.",
    "huggingface_token":      "Revoke on huggingface.co/settings/tokens. Use environment variables or secrets management — never commit tokens.",
    "npm_access_token":       "Revoke on npmjs.com and rotate. Use npm token with read-only scope scoped to specific packages.",
    "docker_registry_auth":   "Rotate Docker registry credentials. Use short-lived tokens or deploy-time secrets injection instead of storing auth configs.",

    # ── Payment & financial ────────────────────────────────────────────
    "stripe_secret_key":      "Revoke immediately in the Stripe dashboard (Developers → API keys). Use restricted keys with minimum required permissions.",
    "stripe_publishable_key": "Publishable keys are low-risk but rotate if exposed alongside a secret key. Restrict allowed domains in Stripe dashboard.",
    "stripe_restricted_key":  "Revoke in Stripe dashboard. Re-issue with minimum required permissions for the specific endpoint.",
    "credit_card":            "Remove card data immediately. Do not store raw PANs — use a PCI-DSS-compliant payment processor (Stripe, Braintree) and store only tokens.",
    "bank_account":           "Remove account details from this location. Use encrypted vaults for financial data and limit access to payment systems only.",
    "routing_number":         "Remove routing number from unencrypted storage. Treat alongside account numbers as sensitive financial data.",
    "iban":                   "Remove IBAN from this location. Encrypt at rest, restrict access, and use tokenization for payment flows.",
    "bitcoin_address":        "Audit transactions to this address for unauthorised activity. Do not expose wallet addresses in public documents.",
    "ethereum_address":       "Audit transactions to this address. Keep wallet addresses out of logs and documents to prevent targeted attacks.",

    # ── PII ────────────────────────────────────────────────────────────
    "ssn":                    "Remove SSN from this file/system immediately. SSNs must be encrypted at rest, access-logged, and stored only in compliance-approved systems (SOC 2 / HIPAA).",
    "us_ssn":                 "Remove SSN from this file/system immediately. SSNs must be encrypted at rest, access-logged, and stored only in compliance-approved systems (SOC 2 / HIPAA).",
    "email":                  "Ensure email addresses are stored with user consent (GDPR Art. 6). Encrypt PII columns at rest and enforce access controls.",
    "email_address":          "Ensure email addresses are stored with user consent (GDPR Art. 6). Encrypt PII columns at rest and enforce access controls.",
    "phone_us":               "Phone numbers are PII under GDPR/CCPA. Store encrypted, obtain user consent, and do not include in logs or documents.",
    "phone_number":           "Phone numbers are PII under GDPR/CCPA. Store encrypted, obtain user consent, and do not include in logs or documents.",
    "person":                 "Personal names are PII. Anonymise or pseudonymise in non-production environments and restrict access in production.",
    "dob":                    "Date of birth is sensitive PII. Encrypt at rest, apply strict access controls, and exclude from logs.",
    "passport":               "Passport numbers require strong protection. Encrypt at rest, log all access, and never store in plaintext documents.",
    "us_passport":            "Passport numbers require strong protection. Encrypt at rest, log all access, and never store in plaintext documents.",
    "drivers_license":        "Driver's licence numbers are regulated PII. Apply encryption, access logging, and data minimisation.",
    "medical_record":         "Medical data is protected under HIPAA. Encrypt, restrict access to authorised personnel, and audit all access.",
    "npi_number":             "NPI numbers combined with other data can identify healthcare providers. Limit exposure and apply appropriate access controls.",
    "ndc_code":               "NDC codes in patient context may be PHI under HIPAA. Review storage and access controls.",
    "dea_number":             "DEA numbers identify prescribers and are sensitive. Encrypt and restrict access.",

    # ── Private keys & certificates ───────────────────────────────────
    "private_key":            "Revoke and regenerate the key pair immediately. Store private keys in a hardware security module (HSM) or secrets manager — never in code or documents.",
    "ssh_private_key":        "Revoke the key on all servers it accesses. Generate a new key pair and store the private key only in ~/.ssh with 600 permissions.",
    "pgp_private_key":        "Revoke the PGP key and generate a new pair. Never store private keys outside a secure keychain or HSM.",
    "ecdsa_private_key":      "Revoke and regenerate the key pair. Store in an HSM or dedicated secrets manager.",
    "certificate":            "If the certificate's private key is exposed, revoke and reissue immediately via your CA.",
    "jwt_token":              "Invalidate the token by rotating the signing secret or adding it to a denylist. Use short expiry times (15 min) for JWTs.",

    # ── Messaging & webhook tokens ─────────────────────────────────────
    "slack_api_token":        "Revoke on api.slack.com/apps. Use Slack's OAuth scopes with minimal permissions and store tokens in a vault.",
    "slack_webhook":          "Regenerate the webhook URL in Slack. Treat webhook URLs as secrets — they allow anyone to post to your channel.",
    "discord_webhook":        "Delete and recreate the webhook in Discord server settings. Do not share webhook URLs in public or version-controlled files.",
    "telegram_bot_token":     "Revoke via @BotFather (/revoke). Rotate immediately if exposed — bot tokens grant full control of the bot.",
    "pagerduty_key":          "Rotate in PagerDuty (User → User Settings → API Access). Use integration-specific keys with minimal scope.",
    "twilio_account_sid":     "Rotate Twilio credentials in console.twilio.com. SIDs combined with auth tokens allow full account access.",
    "twilio_auth_token":      "Rotate immediately in console.twilio.com. Auth tokens provide full API access to your Twilio account.",
    "sendgrid_api_key":       "Revoke on app.sendgrid.com (Settings → API Keys). Issue scoped keys with only the permissions needed.",
    "mailgun_api_key":        "Revoke in Mailgun dashboard. Issue domain-scoped keys with minimum permissions.",

    # ── Database & infrastructure ──────────────────────────────────────
    "db_connection_string":   "Rotate database credentials immediately. Use a secrets manager to inject credentials at runtime — never hardcode connection strings.",
    "bearer_token":           "Revoke the token at the issuing service. Use short-lived tokens with refresh flows and store in secure, httpOnly cookies or a vault.",
    "generic_api_key":        "Rotate this API key at the issuing service. Store API keys in environment variables or a secrets manager, not in code or documents.",
    "mac_address":            "MAC addresses can be used for device fingerprinting. Avoid logging or storing unless strictly necessary.",

    # ── Code security ──────────────────────────────────────────────────
    "hardcoded_password":     "Remove the hardcoded password immediately. Store credentials in environment variables (os.getenv) or a vault such as HashiCorp Vault.",
    "password_in_code":       "Remove the hardcoded password immediately. Store credentials in environment variables (os.getenv) or a vault such as HashiCorp Vault.",
    "sql_injection":          "Use parameterised queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). Never interpolate user input into SQL strings.",
    "cross_site_scripting":   "Sanitise and encode all user input before rendering. Use frameworks that auto-escape output (React, Jinja2 with autoescape=True).",
    "command_injection":      "Never pass user input to shell commands. Use subprocess with a list of arguments (shell=False) and validate all inputs.",
    "insecure_deserialization": "Do not deserialise untrusted data with pickle or yaml.load(). Use json.loads() or a schema-validated parser.",
    "vulnerable_logic":       "Avoid dangerous functions (eval, exec). Use ast.literal_eval() for safe evaluation of literals.",
    "path_traversal":         "Never build file paths from unsanitized request input. Resolve the path and verify it stays within an allowed base directory (os.path.realpath + startswith check), or use a UUID/whitelist lookup instead of a raw filename.",
    "weak_cryptography":      "Do not use MD5/SHA1 for password hashing or DES/RC4/ECB for encryption. Use bcrypt/scrypt/argon2 for passwords and AES-GCM for symmetric encryption.",
    "ssrf":                   "Never pass a user-supplied URL directly to an HTTP client. Validate against an allowlist of hosts/schemes, and block requests to internal/link-local IP ranges (169.254.0.0/16, 10.0.0.0/8, etc.).",
    "xxe":                    "Disable external entity resolution when parsing XML (lxml: resolve_entities=False, no_network=True; Java: disable DOCTYPE declarations on the parser factory).",
    "ssti":                   "Never render a template built from user input. Pass user data as template variables, not as the template string itself, and rely on the engine's auto-escaping.",
    "open_redirect":          "Validate any redirect target against an allowlist of known-safe paths/hosts before redirecting, or restrict to relative paths within your own app.",
    "ldap_injection":         "Escape special LDAP filter characters in user input, or build filters with a library helper (e.g. ldap3's escape_filter_chars / filter_format) instead of string concatenation.",
    "nosql_injection":        "Cast/validate query values to expected primitive types before using them in a query (reject dict/object values from user input) so operators like $ne/$gt can't be injected.",
    "insecure_randomness":    "Use a cryptographically secure generator for tokens, session IDs, and password-reset codes — secrets.token_urlsafe() in Python, crypto.randomBytes() in Node — never random()/Math.random().",
    "sensitive_keyword":      "Review this document for sensitive data. Remove or redact any credentials, PII, or confidential information before sharing.",

    # ── Network ────────────────────────────────────────────────────────
    "url":                    "Verify this URL does not expose credentials in query parameters (e.g. ?token=...). Use POST with encrypted body for sensitive data.",
    "ip_address":             "Internal IP addresses in public documents can aid reconnaissance. Remove or anonymise before sharing externally.",

    # ── Dependencies ───────────────────────────────────────────────────
    "known_vulnerability":    "Upgrade to a patched version (see fixed_versions on this finding). If no fix exists yet, check the advisory for a mitigating workaround or pin an alternative package.",

    "default":                "Remove or redact this sensitive data. Store secrets in a vault, encrypt PII at rest, and follow your organisation's data handling policy.",
}


def get_remediation(issue_type: str) -> str:
    """Return the most specific remediation for a given finding type."""
    key = (issue_type or "").lower()

    if key in KB:
        return KB[key]

    # Keyword fallbacks for compound or variant type strings.
    # NoSQL must be checked before the generic "sql" substring match below
    # ("nosql" contains "sql") — same reasoning applies to any future type
    # string that happens to embed another key's substring.
    if "nosql" in key or "mongo" in key: return KB["nosql_injection"]
    if "password" in key:        return KB["hardcoded_password"]
    if "aws" in key:             return KB["aws_access_key"]
    if "stripe" in key:          return KB["stripe_secret_key"]
    if "github" in key:          return KB["github_token"]
    if "slack" in key:           return KB["slack_api_token"]
    if "private_key" in key or "ssh" in key: return KB["ssh_private_key"]
    if "credit" in key:          return KB["credit_card"]
    if "ssn" in key:             return KB["ssn"]
    if "email" in key:           return KB["email"]
    if "phone" in key:           return KB["phone_number"]
    if "sql" in key:             return KB["sql_injection"]
    if "xss" in key or "script" in key: return KB["cross_site_scripting"]
    if "command" in key or "shell" in key: return KB["command_injection"]
    if "pickle" in key or "serial" in key: return KB["insecure_deserialization"]
    if "eval" in key or "exec" in key: return KB["vulnerable_logic"]
    if "path" in key or "traversal" in key: return KB["path_traversal"]
    if "crypto" in key or "cipher" in key: return KB["weak_cryptography"]
    if "ssrf" in key or "request forgery" in key: return KB["ssrf"]
    if "xxe" in key or "external entity" in key: return KB["xxe"]
    if "ssti" in key or "template injection" in key: return KB["ssti"]
    if "redirect" in key:        return KB["open_redirect"]
    if "ldap" in key:            return KB["ldap_injection"]
    if "random" in key:          return KB["insecure_randomness"]
    if "cve" in key or "vuln" in key: return KB["known_vulnerability"]
    if "token" in key or "bearer" in key: return KB["bearer_token"]
    if "api_key" in key or "apikey" in key: return KB["generic_api_key"]
    if "webhook" in key:         return KB["slack_webhook"]
    if "certificate" in key or "cert" in key: return KB["certificate"]
    if "passport" in key:        return KB["passport"]
    if "medical" in key:         return KB["medical_record"]

    return KB["default"]
