package com.cryptoscanner;

import com.cryptoscanner.model.Finding;
import com.cryptoscanner.policy.PolicyEvaluator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PolicyEvaluatorTest {
    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    @Test
    void flagsMd5Finding() {
        Finding finding = new Finding("sample.c", 10, "MD5_Init", "hashing", "ctx", null);
        evaluator.applyFallbackPolicy(finding);
        assertTrue(finding.isFlaggedByPolicy());
    }

    @Test
    void flagsEncryptionWithWeakKeySize() {
        Finding finding = new Finding("sample.c", 11, "AES_set_encrypt_key", "encryption", "key,64,ctx", 64);
        evaluator.applyFallbackPolicy(finding);
        assertTrue(finding.isFlaggedByPolicy());
    }

    @Test
    void sha256IsNotDeny() {
        Finding finding = new Finding("sample.c", 12, "SHA256_Init", "hashing", "ctx", null);
        evaluator.applyFallbackPolicy(finding);
        assertFalse(finding.isFlaggedByPolicy());
        assertTrue(finding.getPolicyReason().startsWith("warn"));
    }
}
