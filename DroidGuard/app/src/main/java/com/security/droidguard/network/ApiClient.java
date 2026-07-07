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

public class ApiClient {
    private static final String TAG = "ApiClient";
    private static final String BASE_URL = BuildConfig.BASE_URL;
    private static final int TIMEOUT_MS = 15_000; // 15 s

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
            throw new Exception("Server returned HTTP " + responseCode + ": " + readStream(conn.getErrorStream()));
        }
    }

    // POST /api/analyze
    public String uploadApk(String apkPath, String hash, String appName) throws Exception {
        File apkFile = new File(apkPath);

        if (!apkFile.exists()) {
            throw new Exception("APK file not found at path: " + apkPath);
        }

        String boundary = "===" + System.currentTimeMillis() + "===";
        String lineEnd = "\r\n";
        String twoHyphens = "--";

        String encodedAppName;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            encodedAppName = URLEncoder.encode(appName, StandardCharsets.UTF_8);
        } else {
            encodedAppName = URLEncoder.encode(appName, "UTF-8");
        }

        String urlString = BASE_URL + "/analyze?hash=" + hash + "&appName=" + encodedAppName;
        HttpURLConnection conn = getHttpURLConnection(urlString, boundary);

        try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
             FileInputStream fis = new FileInputStream(apkFile)) {

            dos.writeBytes(twoHyphens + boundary + lineEnd);
            dos.writeBytes("Content-Disposition: form-data; name=\"file\"; filename=\"" + apkFile.getName() + "\"" + lineEnd);
            dos.writeBytes("Content-Type: application/vnd.android.package-archive" + lineEnd);
            dos.writeBytes(lineEnd);

            int bytesRead;
            int bufferSize = 8_192; // 8KB buffer
            byte[] buffer = new byte[bufferSize];

            Log.d(TAG, "Starting APK upload chunking...");
            while ((bytesRead = fis.read(buffer, 0, bufferSize)) > 0) {
                dos.write(buffer, 0, bytesRead);
            }

            dos.writeBytes(lineEnd);
            dos.writeBytes(twoHyphens + boundary + twoHyphens + lineEnd);
            dos.flush();
        }

        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
            return readStream(conn.getInputStream());
        } else {
            throw new Exception("Upload failed with HTTP " + responseCode + ": " + readStream(conn.getErrorStream()));
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
            throw new Exception("Status poll failed with HTTP " + responseCode + ": " + readStream(conn.getErrorStream()));
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
            throw new Exception("Failed to fetch summary. HTTP " + responseCode + ": " + readStream(conn.getErrorStream()));
        }
    }

    @NonNull
    private static HttpURLConnection getHttpURLConnection(String urlString, String boundary) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(60_000);
        conn.setDoInput(true);
        conn.setDoOutput(true);
        conn.setUseCaches(false);

        conn.setChunkedStreamingMode(8_192);

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

        return conn;
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