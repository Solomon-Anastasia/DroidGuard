package com.security.droidguard.network;

import java.util.concurrent.atomic.AtomicBoolean;

public final class AnalysisHandle {
    private volatile String jobId;
    private final AtomicBoolean cancelled;

    AnalysisHandle(AtomicBoolean cancelled) {
        this.cancelled = cancelled;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    public String getJobId() {
        return jobId;
    }
}