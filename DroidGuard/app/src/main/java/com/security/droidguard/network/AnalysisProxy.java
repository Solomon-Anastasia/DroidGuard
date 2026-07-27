package com.security.droidguard.network;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

import com.security.droidguard.BuildConfig;
import com.security.droidguard.R;
import com.security.droidguard.utils.HashUtils;

import org.json.JSONObject;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

public class AnalysisProxy {
    private static final String WS_BASE_URL = BuildConfig.WS_BASE_URL;
    private static final int MAX_CONCURRENT_ANALYSES = 10;

    private final Handler mainHandler;
    private final OkHttpClient webSocketClient;
    private final ExecutorService executor;
    private final Context context;

    private final ApiClient apiClient;

    private static final String TAG = "AnalysisProxy";

    public AnalysisProxy(Context context) {
        this.context = context;
        this.apiClient = new ApiClient();
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.executor = Executors.newFixedThreadPool(MAX_CONCURRENT_ANALYSES);
        this.webSocketClient = new OkHttpClient.Builder()
                .pingInterval(25, TimeUnit.SECONDS)
                .build();
    }

    public AnalysisHandle startAnalysis(String apkPath, String appName, AnalysisCallback callback) {
        AtomicBoolean cancelled = new AtomicBoolean(false);
        AnalysisHandle handle = new AnalysisHandle(cancelled);

        executor.execute(() -> {
            try {
                if (cancelled.get())
                    return;

                String fileHash = HashUtils.calculateSHA256(apkPath);
                if (fileHash == null) {
                    postError(callback, cancelled, "Failed to calculate SHA-256 hash locally!");
                    return;
                }

                Log.d(TAG, "Target APK Hash: " + fileHash);
                if (cancelled.get())
                    return;

                String checkResponseStr = apiClient.checkHash(fileHash);
                JSONObject checkJson = new JSONObject(checkResponseStr);
                String state = checkJson.optString("state", "NEW");

                if ("CACHED".equals(state)) {
                    Log.d(TAG, "Existing app! Returning immediate results");

                    JSONObject reportObj = checkJson.optJSONObject("yaraReport");
                    String cachedReport = (reportObj != null) ? reportObj.toString() : "{}";

                    postSuccess(callback, cancelled, cachedReport);
                } else if ("PENDING".equals(state)) {
                    Log.d(TAG, "Job already scanning. Attaching to WebSocket feed");

                    String jobId = checkJson.getString("jobId");
                    handle.setJobId(jobId);

                    postProgress(callback, cancelled, "JOB_ID_ATTACHED:" + jobId);
                    startWebSocketListening(jobId, System.currentTimeMillis(), callback, cancelled);
                } else {
                    Log.d(TAG, "New file detected. Initiating multipart upload...");

                    if (cancelled.get())
                        return;

                    String uploadResponseStr = apiClient.uploadApk(apkPath, fileHash, appName);
                    JSONObject uploadJson = new JSONObject(uploadResponseStr);
                    String jobId = uploadJson.getString("jobId");

                    handle.setJobId(jobId);

                    postProgress(callback, cancelled, "JOB_ID_ATTACHED:" + jobId);

                    startWebSocketListening(jobId, System.currentTimeMillis(), callback, cancelled);
                }
            } catch (Exception e) {
                Log.e(TAG, "Analysis pipeline failed", e);
                postError(callback, cancelled, "Network or parsing error: " + e.getMessage());
            }
        });

        return handle;
    }

    public AnalysisHandle resumePolling(String jobId,
                                        long originalStartTime,
                                        AnalysisCallback callback) {
        AtomicBoolean cancelled = new AtomicBoolean(false);
        AnalysisHandle handle = new AnalysisHandle(cancelled);
        handle.setJobId(jobId);

        executor.execute(() -> {
            Log.d(TAG, "Resuming connection for recovered job ID: " + jobId);
            startWebSocketListening(jobId, originalStartTime, callback, cancelled);
        });

        return handle;
    }

    private void startWebSocketListening(String jobId, long startTime,
                                         AnalysisCallback callback, AtomicBoolean cancelled) {
        try {
            String statusResponseStr = apiClient.pollStatus(jobId);
            JSONObject statusJson = new JSONObject(statusResponseStr);
            String currentStatus = statusJson.getString("status");

            if ("COMPLETED".equalsIgnoreCase(currentStatus) ||
                    "FAILED".equalsIgnoreCase(currentStatus) ||
                    "ABORTED".equalsIgnoreCase(currentStatus)) {
                Log.d(TAG, "Job already finished while app was disconnected");
                processServerResponse(statusJson, callback, cancelled, startTime);
                return;
            }
        } catch (Exception e) {
            Log.w(TAG, "Initial status check failed, proceeding to WebSocket connection...");
        }

        AtomicBoolean serverResponded = new AtomicBoolean(false);
        executor.execute(() -> {
            while (!serverResponded.get() && !cancelled.get()) {
                long elapsedMillis = System.currentTimeMillis() - startTime;
                long seconds = (elapsedMillis / 1_000) % 60;
                long minutes = (elapsedMillis / (1_000 * 60)) % 60;
                String timeFormatted = String.format(Locale.US, "%02d:%02d", minutes, seconds);

                postProgress(callback,
                        cancelled,
                        context.getString(R.string.status_analyzing_time, timeFormatted)
                );

                try {
                    Thread.sleep(1_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });

        Request request = new Request.Builder()
                .url(WS_BASE_URL + jobId)
                .build();

        webSocketClient.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onOpen(@NonNull WebSocket webSocket,
                               @NonNull Response response) {
                Log.d(TAG, "WebSocket connected for job ID: " + jobId);
            }

            @Override
            public void onMessage(@NonNull WebSocket webSocket,
                                  @NonNull String text) {
                Log.d(TAG, "WebSocket received payload: " + text);
                serverResponded.set(true);

                try {
                    JSONObject json = new JSONObject(text);
                    processServerResponse(json, callback, cancelled, startTime);
                } catch (Exception e) {
                    postError(callback, cancelled, "Failed to parse server response");
                }

                webSocket.close(1_000, "Received final report");
            }

            @Override
            public void onFailure(@NonNull WebSocket webSocket,
                                  @NonNull Throwable t,
                                  Response response) {
                Log.w(TAG, "WebSocket dropped, attempting to reconnect", t);
                if (cancelled.get()) return;

                startWebSocketListening(jobId, startTime, callback, cancelled);
            }

            @Override
            public void onClosed(@NonNull WebSocket webSocket,
                                 int code,
                                 @NonNull String reason) {
                serverResponded.set(true);
            }
        });
    }

    private void processServerResponse(JSONObject json, AnalysisCallback callback,
                                       AtomicBoolean cancelled, long startTime) {
        String status = json.optString("status");

        if ("COMPLETED".equalsIgnoreCase(status)) {
            long elapsedMillis = System.currentTimeMillis() - startTime;
            long seconds = (elapsedMillis / 1_000) % 60;
            long minutes = (elapsedMillis / (1_000 * 60)) % 60;
            String scanDuration = String.format(Locale.US, "%02d:%02d", minutes, seconds);

            JSONObject reportObj = json.optJSONObject("yaraReport");
            if (reportObj == null) {
                reportObj = new JSONObject();
            }

            try {
                reportObj.put("scan_duration_formatted", scanDuration);
            } catch (Exception e) {
                Log.e(TAG, "Failed to inject scan duration", e);
            }

            String reportStr = reportObj.toString();
            postSuccess(callback, cancelled, reportStr);
        } else if ("FAILED".equalsIgnoreCase(status)) {
            postError(callback, cancelled, "Analysis worker failed to process the APK!");
        } else if ("ABORTED".equalsIgnoreCase(status)) {
            postError(callback, cancelled, "Scan was cancelled by the server");
        }
    }

    public void cancelAnalysisOnServer(String jobId) {
        executor.execute(() -> {
            try {
                apiClient.cancelJob(jobId);
                Log.d(TAG, "Sent abort signal to Gateway for job ID: " + jobId);
            } catch (Exception e) {
                Log.e(TAG, "Failed to send cancel signal to server", e);
            }
        });
    }

    private void postSuccess(AnalysisCallback callback, AtomicBoolean cancelled, String report) {
        if (cancelled.get())
            return;

        mainHandler.post(() -> {
            if (!cancelled.get()) callback.onSuccess(report);
        });
    }

    private void postProgress(AnalysisCallback callback, AtomicBoolean cancelled, String status) {
        if (cancelled.get())
            return;

        mainHandler.post(() -> {
            if (!cancelled.get()) callback.onProgress(status);
        });
    }

    private void postError(AnalysisCallback callback, AtomicBoolean cancelled, String error) {
        if (cancelled.get())
            return;

        mainHandler.post(() -> {
            if (!cancelled.get()) callback.onError(error);
        });
    }
}