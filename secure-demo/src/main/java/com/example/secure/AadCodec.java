package com.example.secure;

import java.nio.charset.StandardCharsets;

/**
 * Construye el AAD descrito en la seccion 8 del documento:
 * request_id | source_service | destination_service | timestamp | schema_version
 */
public final class AadCodec {

    private static final String SCHEMA_VERSION = "v1";

    private AadCodec() {}

    public static byte[] build(
            String requestId,
            String sourceService,
            String destinationService,
            long timestampEpochSeconds) {

        String aad = String.join("|",
            requestId,
            sourceService,
            destinationService,
            Long.toString(timestampEpochSeconds),
            SCHEMA_VERSION
        );

        return aad.getBytes(StandardCharsets.UTF_8);
    }
}
