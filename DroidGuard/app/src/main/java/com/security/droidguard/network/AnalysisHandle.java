package com.security.droidguard.network;

import java.util.concurrent.atomic.AtomicBoolean;

public final class AnalysisHandle {
    private final AtomicBoolean cancelled;

    AnalysisHandle(AtomicBoolean cancelled) {
        this.cancelled = cancelled;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public boolean isCancelled() {
        return cancelled.get();
    }
}