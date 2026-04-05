package com.cryptoscanner;

import com.cryptoscanner.model.Finding;
import com.cryptoscanner.scanner.OpenSSLDetector;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OpenSSLDetectorTest {
    private final OpenSSLDetector detector = new OpenSSLDetector();

    @Test
    void detectsEncryptInitAsEncryption() {
        Finding finding = detector.detect("sample.c", 10, "EVP_EncryptInit_ex", "ctx, EVP_aes_256_cbc(), NULL, key, iv");
        assertNotNull(finding);
        assertEquals("encryption", finding.getCategory());
    }

    @Test
    void detectsMd5AsHashing() {
        Finding finding = detector.detect("sample.c", 12, "MD5_Init", "ctx");
        assertNotNull(finding);
        assertEquals("hashing", finding.getCategory());
    }

    @Test
    void returnsNullForNonOpenSslCall() {
        Finding finding = detector.detect("sample.c", 2, "printf", "\"hello\"");
        assertNull(finding);
    }

    @Test
    void extractsKeySizeWhenPresent() {
        Finding finding = detector.detect("sample.c", 20, "AES_set_encrypt_key", "key, 256, &aes_key");
        assertNotNull(finding);
        assertEquals(256, finding.getExtractedKeySize());
    }

    @Test
    void mapsRsaGenerateKeyToKeyExchange() {
        Finding finding = detector.detect("sample.c", 22, "RSA_generate_key", "2048, 65537, NULL, NULL");
        assertNotNull(finding);
        assertEquals("key-exchange", finding.getCategory());
    }
}
