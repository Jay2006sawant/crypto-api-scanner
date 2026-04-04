package com.cryptoscanner.scanner;

import com.cryptoscanner.model.Finding;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OpenSSLDetector {
    private static final Map<String, String> OPENSSL_FUNCTIONS = new LinkedHashMap<>();
    private static final Pattern NUMBER_PATTERN = Pattern.compile("\\b(\\d{2,4})\\b");

    static {
        OPENSSL_FUNCTIONS.put("EVP_EncryptInit_ex", "encryption");
        OPENSSL_FUNCTIONS.put("EVP_DecryptInit_ex", "encryption");
        OPENSSL_FUNCTIONS.put("EVP_DigestInit", "hashing");
        OPENSSL_FUNCTIONS.put("EVP_DigestInit_ex", "hashing");
        OPENSSL_FUNCTIONS.put("RSA_generate_key", "key-exchange");
        OPENSSL_FUNCTIONS.put("RSA_generate_key_ex", "key-exchange");
        OPENSSL_FUNCTIONS.put("DH_generate_key", "key-exchange");
        OPENSSL_FUNCTIONS.put("HMAC_Init_ex", "hashing");
        OPENSSL_FUNCTIONS.put("AES_set_encrypt_key", "encryption");
        OPENSSL_FUNCTIONS.put("AES_set_decrypt_key", "encryption");
        OPENSSL_FUNCTIONS.put("EVP_PKEY_keygen", "key-exchange");
        OPENSSL_FUNCTIONS.put("SHA256_Init", "hashing");
        OPENSSL_FUNCTIONS.put("SHA512_Init", "hashing");
        OPENSSL_FUNCTIONS.put("MD5_Init", "hashing");
    }

    public Finding detect(String filePath, int lineNumber, String functionName, String rawArguments) {
        String category = OPENSSL_FUNCTIONS.get(functionName);
        if (category == null) {
            return null;
        }
        Integer keySize = extractKeySize(rawArguments);
        return new Finding(filePath, lineNumber, functionName, category, rawArguments, keySize);
    }

    private Integer extractKeySize(String rawArguments) {
        if (rawArguments == null || rawArguments.isBlank()) {
            return null;
        }
        String[] args = rawArguments.split(",");
        if (args.length < 2) {
            return null;
        }

        int[] candidateIndices = {1, 2};
        for (int index : candidateIndices) {
            if (index < args.length) {
                Matcher matcher = NUMBER_PATTERN.matcher(args[index]);
                if (matcher.find()) {
                    return Integer.parseInt(matcher.group(1));
                }
            }
        }
        return null;
    }
}
