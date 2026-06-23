package com.example.yaradroid.network;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.example.yaradroid.utils.HashUtils;

import org.json.JSONObject;

public class AnalysisProxy {
    private static final String TAG = "AnalysisProxy";
    private final ApiClient apiClient;
    private final Handler mainHandler; // Ensures callbacks run on the UI thread

    public AnalysisProxy() {
        this.apiClient = new ApiClient();
        this.mainHandler = new Handler(Looper.getMainLooper());
    }

    public void startAnalysis(String apkPath, AnalysisCallback callback) {
        new Thread(() -> {
            try {
                String fileHash = HashUtils.calculateSHA256(apkPath);

                if (fileHash == null) {
                    postError(callback, "Failed to calculate SHA-256 hash locally!");
                    return;
                }

                Log.d(TAG, "Target APK Hash: " + fileHash);

                String checkResponseStr = apiClient.checkHash(fileHash);
                JSONObject checkJson = new JSONObject(checkResponseStr);

                String state = checkJson.optString("state", "NEW");

                if ("CACHED".equals(state)) {
                    Log.d(TAG, "Existing app! Returning immediate results");

                    String cachedReport = checkJson.getString("yaraReport");
                    postSuccess(callback, cachedReport);
                } else if ("PENDING".equals(state)) {
                    Log.d(TAG, "Job already in RabbitMQ. Attaching to existing polling queue");

                    String jobId = checkJson.getString("jobId");
                    startPolling(jobId, callback);
                } else {
                    // The Route Phase: entirely new file, proceed with 50MB+ upload
                    Log.d(TAG, "New file detected. Initiating multipart upload...");

                    String uploadResponseStr = apiClient.uploadApk(apkPath);
                    JSONObject uploadJson = new JSONObject(uploadResponseStr);
                    String jobId = uploadJson.getString("jobId");

                    startPolling(jobId, callback);
                }
            } catch (Exception e) {
                Log.e(TAG, "Analysis pipeline failed", e);
                postError(callback, "Network or parsing error: " + e.getMessage());
            }
        }).start();
    }

    private void startPolling(String jobId, AnalysisCallback callback) throws Exception {
        boolean completed = false;
        int maxAttempts = 60; // Timeout 5 min
        int attempts = 0;

        Log.d(TAG, "Started polling API Gateway for JobID: " + jobId);

        while (!completed && attempts < maxAttempts) {
            String statusResponseStr = apiClient.pollStatus(jobId);
            JSONObject statusJson = new JSONObject(statusResponseStr);

            String currentStatus = statusJson.getString("status");

            if ("COMPLETED".equalsIgnoreCase(currentStatus)) {
                completed = true;

                String report = statusJson.getString("yaraReport");
                Log.d(TAG, "Analysis worker finished job.");

                postSuccess(callback, report);
            } else if ("FAILED".equalsIgnoreCase(currentStatus)) {
                Log.e(TAG, "Asynchronous analysis worker failed processing the APK!");

                postError(callback, "Analysis worker failed to process the APK!");
                return;
            } else {
                // PENDING / PROCESSING
                attempts++;
                Thread.sleep(5_000); // 5s polling interval
            }
        }

        if (!completed) {
            postError(callback, "Polling timed out while waiting for the analysis worker");
        }
    }

    private void postSuccess(AnalysisCallback callback, String report) {
        mainHandler.post(() -> callback.onSuccess(report));
    }

    private void postError(AnalysisCallback callback, String error) {
        mainHandler.post(() -> callback.onError(error));
    }

    public interface AnalysisCallback {
        void onSuccess(String jsonReport);

        void onError(String error);
    }
}