package com.security.droidguard.network;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.security.droidguard.utils.HashUtils;

import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class AnalysisProxy {
    private static final String TAG = "AnalysisProxy";
    private static final int MAX_CONCURRENT_ANALYSES = 10;

    private final ApiClient apiClient;
    private final Handler mainHandler;
    private final ExecutorService executor;

    public AnalysisProxy() {
        this.apiClient = new ApiClient();
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.executor = Executors.newFixedThreadPool(MAX_CONCURRENT_ANALYSES);
    }

    public AnalysisHandle startAnalysis(String apkPath, String appName, AnalysisCallback callback) {
        AtomicBoolean cancelled = new AtomicBoolean(false);
        AnalysisHandle handle = new AnalysisHandle(cancelled);

        executor.execute(() -> {
            try {
                if (cancelled.get()) return;

                String fileHash = HashUtils.calculateSHA256(apkPath);

                if (fileHash == null) {
                    postError(callback, cancelled, "Failed to calculate SHA-256 hash locally!");
                    return;
                }

                Log.d(TAG, "Target APK Hash: " + fileHash);

                if (cancelled.get()) return;

                String checkResponseStr = apiClient.checkHash(fileHash);
                JSONObject checkJson = new JSONObject(checkResponseStr);

                String state = checkJson.optString("state", "NEW");

                if ("CACHED".equals(state)) {
                    Log.d(TAG, "Existing app! Returning immediate results");

                    JSONObject reportObj = checkJson.optJSONObject("yaraReport");
                    String cachedReport = (reportObj != null) ? reportObj.toString() : "{}";

                    postSuccess(callback, cancelled, cachedReport);
                } else if ("PENDING".equals(state)) {
                    Log.d(TAG, "Job already in RabbitMQ. Attaching to existing polling queue");

                    String jobId = checkJson.getString("jobId");
                    handle.setJobId(jobId);
                    startPolling(jobId, callback, cancelled);
                } else {
                    Log.d(TAG, "New file detected. Initiating multipart upload...");

                    if (cancelled.get()) return;

                    String uploadResponseStr = apiClient.uploadApk(apkPath, fileHash, appName);
                    JSONObject uploadJson = new JSONObject(uploadResponseStr);
                    String jobId = uploadJson.getString("jobId");

                    handle.setJobId(jobId);

                    startPolling(jobId, callback, cancelled);
                }
            } catch (Exception e) {
                Log.e(TAG, "Analysis pipeline failed", e);
                postError(callback, cancelled, "Network or parsing error: " + e.getMessage());
            }
        });

        return handle;
    }

    private void startPolling(String jobId, AnalysisCallback callback, AtomicBoolean cancelled) throws Exception {
        boolean completed = false;
        int maxAttempts = 60 + 60 + 60 + 60; // Timeout 5 min each
        int attempts = 0;

        Log.d(TAG, "Started polling API Gateway for JobID: " + jobId);

        while (!completed && attempts < maxAttempts) {
            if (cancelled.get()) {
                Log.d(TAG, "Polling cancelled by caller for JobID: " + jobId);
                return;
            }

            String statusResponseStr = apiClient.pollStatus(jobId);
            JSONObject statusJson = new JSONObject(statusResponseStr);

            String currentStatus = statusJson.getString("status");

            if ("COMPLETED".equalsIgnoreCase(currentStatus)) {
                completed = true;

                JSONObject reportObj = statusJson.optJSONObject("yaraReport");
                String report = (reportObj != null) ? reportObj.toString() : "{}";

                Log.d(TAG, "Analysis worker finished job.");

                postSuccess(callback, cancelled, report);
            } else if ("FAILED".equalsIgnoreCase(currentStatus)) {
                Log.e(TAG, "Asynchronous analysis worker failed processing the APK!");

                postError(callback, cancelled, "Analysis worker failed to process the APK!");
                return;
            } else {
                attempts++;
                postProgress(callback, cancelled, "Analyzing... (" + attempts + "/" + maxAttempts + ")");

                if (cancelled.get()) return;

                try {
                    Thread.sleep(5_000); // 5s polling interval
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    Log.d(TAG, "Polling interrupted for JobID: " + jobId);
                    return;
                }
            }
        }

        if (!completed) {
            postError(callback, cancelled, "Polling timed out while waiting for the analysis worker");
        }
    }

    public void cancelAnalysisOnServer(String jobId) {
        executor.execute(() -> {
            try {
                // You will need to add this mapping to your ApiClient
                apiClient.cancelJob(jobId);
                Log.d(TAG, "Sent abort signal to Gateway for JobID: " + jobId);
            } catch (Exception e) {
                Log.e(TAG, "Failed to send cancel signal to server", e);
            }
        });
    }

    private void postSuccess(AnalysisCallback callback, AtomicBoolean cancelled, String report) {
        if (cancelled.get()) return;
        mainHandler.post(() -> {
            if (!cancelled.get()) callback.onSuccess(report);
        });
    }

    private void postProgress(AnalysisCallback callback, AtomicBoolean cancelled, String status) {
        if (cancelled.get()) return;
        mainHandler.post(() -> {
            if (!cancelled.get()) callback.onProgress(status);
        });
    }

    private void postError(AnalysisCallback callback, AtomicBoolean cancelled, String error) {
        if (cancelled.get()) return;
        mainHandler.post(() -> {
            if (!cancelled.get()) callback.onError(error);
        });
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}