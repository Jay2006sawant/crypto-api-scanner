# crypto-api-scanner

`crypto-api-scanner` is a Java-based static analysis tool that scans C/C++ code for OpenSSL API usage, extracts cryptographic metadata from matched calls, and writes structured JSON output. It uses an ANTLR4 grammar focused on C-style function call statements, then classifies known OpenSSL functions into encryption, hashing, and key-exchange primitives with contextual metadata like source path, line number, argument payload, and inferred key size hints.

The project also includes a companion policy evaluation stage. After scanning, findings are evaluated against configurable security rules via Open Policy Agent (OPA) over REST (`http://localhost:8181`). If OPA is unavailable, a Java fallback policy engine applies equivalent baseline checks so analysis still completes and produces a per-file pass/fail summary.

## Prerequisites

- Java 17
- Maven 3.9+
- OPA (optional, for REST policy evaluation)

## Build

```bash
mvn clean package
```

## Run

```bash
java -jar target/crypto-api-scanner.jar ./sample_c_files
```

## Run with OPA

1. Start OPA server:
   ```bash
   opa run --server
   ```
2. Load policy:
   ```bash
   opa run --server policies/crypto_policy.rego
   ```
3. Run scanner:
   ```bash
   java -jar target/crypto-api-scanner.jar ./sample_c_files
   ```

## Sample JSON output snippet

```json
{
  "scanTimestamp": "2026-04-06T08:21:15.120Z",
  "totalFilesScanned": 3,
  "totalFindings": 10,
  "findings": [
    {
      "filePath": "sample_c_files/openssl_sample.c",
      "lineNumber": 16,
      "functionName": "EVP_EncryptInit_ex",
      "category": "encryption",
      "rawArguments": "ctx, EVP_aes_256_cbc(), NULL, key, iv",
      "keySize": null,
      "flaggedByPolicy": false,
      "policyReason": "warn: missing encryption key size"
    }
  ]
}
```

## Detected OpenSSL functions

| Function | Category |
|---|---|
| EVP_EncryptInit_ex | encryption |
| EVP_DecryptInit_ex | encryption |
| EVP_DigestInit | hashing |
| EVP_DigestInit_ex | hashing |
| RSA_generate_key | key-exchange |
| RSA_generate_key_ex | key-exchange |
| DH_generate_key | key-exchange |
| HMAC_Init_ex | hashing |
| AES_set_encrypt_key | encryption |
| AES_set_decrypt_key | encryption |
| EVP_PKEY_keygen | key-exchange |
| SHA256_Init | hashing |
| SHA512_Init | hashing |
| MD5_Init | hashing |

## Research notes: OpenSSL vs libsodium vs wolfSSL

OpenSSL provides a broad and mature API surface with many legacy and modern entry points, which improves compatibility but increases detection complexity in static analysis due to overlapping primitives, compatibility wrappers, and multiple initialization styles. Its prevalence in large C ecosystems makes it valuable for real-world benchmarking.

libsodium favors a higher-level, misuse-resistant API design with fewer low-level knobs exposed to users. That generally reduces ambiguity for static analysis because call patterns are more opinionated and algorithm selection is often abstracted behind safer defaults.

wolfSSL offers a compact footprint and embedded focus with OpenSSL-compatibility layers in many deployments. From an analysis perspective, mixed native and compatibility APIs can make detection easier for standard wrappers but harder when projects conditionally compile different backends.

## Known false positive patterns

- Macro expansion can obscure direct API names (for example wrapper macros that expand to OpenSSL functions after preprocessing).
- Indirect function pointers and callback tables can hide concrete callee names from source-level parsing.
- Compatibility abstraction layers may map one symbolic function name to multiple runtime implementations across build targets.
