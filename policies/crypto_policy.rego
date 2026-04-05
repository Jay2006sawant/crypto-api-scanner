package crypto.crypto_policy

default result := {"result": "allow", "reason": "policy checks passed"}

result := {"result": "deny", "reason": "weak algorithm MD5"} if {
    input.functionName == "MD5_Init"
}

result := {"result": "deny", "reason": "encryption key size below 128"} if {
    input.category == "encryption"
    input.keySize != null
    input.keySize < 128
}

result := {"result": "warn", "reason": "missing encryption key size"} if {
    input.category == "encryption"
    input.keySize == null
}
