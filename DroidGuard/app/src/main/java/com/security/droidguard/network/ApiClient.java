package com.security.droidguard.network;

import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;

import com.security.droidguard.BuildConfig;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ApiClient {
    private static final String BASE_URL = BuildConfig.BASE_URL;
    private static final int TIMEOUT_MS = 15_000;

    private final OkHttpClient httpClient = new OkHttpClient();

    private static final String TAG = "ApiClient";

    // GET /api/check?hash={sha256}
    public String checkHash(String sha256) throws Exception {
        URL url = new URL(BASE_URL + "/check?hash=" + sha256);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("GET");
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);

        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            return readStream(conn.getInputStream());
        } else {
            throw new Exception("Server returned HTTP " + responseCode +
                    ": " + readStream(conn.getErrorStream()));
        }
    }

    // POST /api/analyze
    public String uploadApk(String apkPath, String hash, String appName) throws Exception {
        File apkFile = new File(apkPath);
        if (!apkFile.exists()) {
            throw new Exception("APK file not found at path: " + apkPath);
        }

        String encodedAppName;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            encodedAppName = URLEncoder.encode(appName, StandardCharsets.UTF_8);
        } else {
            encodedAppName = URLEncoder.encode(appName, "UTF-8");
        }

        String urlString = BASE_URL + "/analyze?hash=" + hash + "&appName=" + encodedAppName;
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart(
                        "file",
                        apkFile.getName(),
                        RequestBody.create(
                                apkFile,
                                MediaType.parse("application/vnd.android.package-archive")
                        )
                )
                .build();

        Request request = new Request.Builder()
                .url(urlString)
                .post(requestBody)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                return response.body().string();
            } else {
                String errorBody = response.body() != null ? response.body().string() : "Unknown error";
                throw new Exception("Upload failed with HTTP " + response.code() + ": " + errorBody);
            }
        }
    }

    // GET /api/status/{jobId}
    public String pollStatus(String jobId) throws Exception {
        URL url = new URL(BASE_URL + "/status/" + jobId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("GET");
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);

        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            return readStream(conn.getInputStream());
        } else {
            throw new Exception("Status poll failed with HTTP " + responseCode + ": " +
                    readStream(conn.getErrorStream()));
        }
    }

    // GET /api/reports/summary
    public String getReportsSummary() throws Exception {
        URL url = new URL(BASE_URL + "/reports/summary");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("GET");
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);

        int responseCode = conn.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            return readStream(conn.getInputStream());
        } else {
            throw new Exception("Failed to fetch summary. HTTP " + responseCode + ": " +
                    readStream(conn.getErrorStream()));
        }
    }

    public void cancelJob(String jobId) throws Exception {
        URL url = new URL(BASE_URL + "/cancel/" + jobId);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);

        int responseCode = conn.getResponseCode();

        if (responseCode != 200) {
            throw new Exception("Failed to cancel job. Server returned: " + responseCode);
        }

        conn.disconnect();
    }

    // InputStream to String
    private String readStream(InputStream is) throws Exception {
        if (is == null) return "";

        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            sb.append(line).append('\n');
        }

        reader.close();
        return sb.toString().trim();
    }
}