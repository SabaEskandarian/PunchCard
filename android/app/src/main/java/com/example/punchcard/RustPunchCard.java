package com.example.punchcard;

public class RustPunchCard {
    private static native String benchmarkCode();

    public String runRustCode() {
        return benchmarkCode();
    }
}
