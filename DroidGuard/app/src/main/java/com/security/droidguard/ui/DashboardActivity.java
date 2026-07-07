package com.security.droidguard.ui;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.security.droidguard.MainActivity;
import com.security.droidguard.R;
import com.security.droidguard.network.ApiClient;

import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DashboardActivity extends AppCompatActivity {

    private TextView textTotalScanned, textSafeApps, textThreatsFound;
    private MaterialCardView cardActiveScan;
    private TextView textScanningAppName, textScanStatusLog;
    private MaterialButton btnOpenAppList;

    // Track state dynamically
    private int totalInstalledUserApps = 0;

    // Networking setup
    private final ApiClient apiClient = new ApiClient();
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);

        // Map UI Elements
        textTotalScanned = findViewById(R.id.textTotalScanned);
        textSafeApps = findViewById(R.id.textSafeApps);
        textThreatsFound = findViewById(R.id.textThreatsFound);

        cardActiveScan = findViewById(R.id.cardActiveScan);
        textScanningAppName = findViewById(R.id.textScanningAppName);
        textScanStatusLog = findViewById(R.id.textScanStatusLog);

        btnOpenAppList = findViewById(R.id.btnOpenAppList);

        btnOpenAppList.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, MainActivity.class);
            startActivity(intent);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadDashboardStats();
    }

    private void loadDashboardStats() {
        updateDashboardUI(0, 0, 0);

        fetchMetricsFromGateway();
    }

    private void fetchMetricsFromGateway() {
        executorService.execute(() -> {
            try {
                String jsonResponse = apiClient.getReportsSummary();
                JSONObject json = new JSONObject(jsonResponse);

                int totalScanned = json.getInt("totalScanned");
                int safeCount = json.getInt("safeCount");
                int suspiciousCount = json.getInt("suspiciousCount");

                runOnUiThread(() -> updateDashboardUI(totalScanned, safeCount, suspiciousCount));

            } catch (Exception e) {
                e.printStackTrace();
                runOnUiThread(() -> updateDashboardUI(0, 0, 0));
            }
        });
    }

    private void updateDashboardUI(int totalScanned, int safeCount, int suspiciousCount) {
        textTotalScanned.setText(String.valueOf(totalScanned));
        textSafeApps.setText(String.valueOf(safeCount));
        textThreatsFound.setText(String.valueOf(suspiciousCount));
    }

    /**
     * Call this public method when a background pipeline notification or proxy callback
     * broadcasts a state change regarding an ongoing app execution job status update.
     */
    public void updateActiveScanProgress(String appName, String currentLogStatus) {
        runOnUiThread(() -> {
            if (cardActiveScan.getVisibility() == View.GONE) {
                cardActiveScan.setVisibility(View.VISIBLE);
            }
            textScanningAppName.setText("Scanning: " + appName);
            textScanStatusLog.setText("Status: " + currentLogStatus);
        });
    }

    public void hideActiveScanProgress() {
        runOnUiThread(() -> cardActiveScan.setVisibility(View.GONE));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Prevent memory leaks when the activity is destroyed
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
}