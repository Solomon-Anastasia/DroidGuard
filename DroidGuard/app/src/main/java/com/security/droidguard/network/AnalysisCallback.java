package com.security.droidguard.network;

public interface AnalysisCallback {
    void onSuccess(String jsonReport);

    void onProgress(String status);

    void onError(String error);
}
