package com.chetankhandave.utility.certificate;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Shared integrity-checked loading; never retains or modifies the caller's password. */
final class KeyStoreLoader {
    private KeyStoreLoader() { }
    static KeyStore load(Path file, String type, char[] password)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(password, "storePassword (integrity verification required)");
        if (!"JKS".equalsIgnoreCase(type) && !"PKCS12".equalsIgnoreCase(type)) {
            throw new IllegalArgumentException("Use JKS or PKCS12");
        }
        KeyStore store = KeyStore.getInstance(type);
        char[] copy = password.clone();
        try (InputStream input = Files.newInputStream(file)) {
            store.load(input, copy);
        } finally {
            Arrays.fill(copy, '\0');
        }
        return store;
    }
}
