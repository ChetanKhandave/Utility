package com.chetankhandave.utility.certificate;

import java.security.*;
import java.util.*;

/** Proves private-key possession by signing a random challenge, never exporting the key. */
public final class KeyPairVerifier {
    public enum Result { MATCH, MISMATCH, UNSUPPORTED }
    public Result verify(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        Objects.requireNonNull(privateKey,"privateKey"); Objects.requireNonNull(publicKey,"publicKey");
        if(!privateKey.getAlgorithm().equalsIgnoreCase(publicKey.getAlgorithm())) return Result.MISMATCH;
        String algorithm;
        switch(privateKey.getAlgorithm().toUpperCase(Locale.ROOT)) {
            case "RSA": algorithm="SHA256withRSA"; break;
            case "EC": algorithm="SHA256withECDSA"; break;
            case "DSA": algorithm="SHA256withDSA"; break;
            default: return Result.UNSUPPORTED;
        }
        byte[] challenge=new byte[32]; new SecureRandom().nextBytes(challenge);
        Signature signer=Signature.getInstance(algorithm);
        signer.initSign(privateKey); signer.update(challenge);
        byte[] signature=signer.sign();
        signer.initVerify(publicKey); signer.update(challenge);
        return signer.verify(signature) ? Result.MATCH : Result.MISMATCH;
    }
}
