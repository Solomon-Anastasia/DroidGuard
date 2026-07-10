package com.security.droidguard.ui.activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.Observer;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.security.droidguard.MainActivity;
import com.security.droidguard.R;
import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.database.ScanHistoryDao;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ApiClient;
import com.security.droidguard.network.ScanManager;

import org.json.JSONObject;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DashboardActivity extends AppCompatActivity {

    private TextView textTotalScanned, textSafeApps, textThreatsFound;
    private MaterialCardView cardActiveScan;
    private TextView textScanningAppName, textScanStatusLog;
    private MaterialButton btnOpenAppList;

    private MaterialCardView cardCompletedScans;
    private TextView textCompletedTitle;

    private ScanHistoryDao scanHistoryDao;
    private SwipeRefreshLayout swipeRefreshLayout;

    private final ApiClient apiClient = new ApiClient();
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);

        ScanManager.getInstance().init(getApplicationContext());

        swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout);

        // Configure color scheme for refresh spinner
        swipeRefreshLayout.setColorSchemeColors(
                com.google.android.material.color.MaterialColors.getColor(swipeRefreshLayout, androidx.appcompat.R.attr.colorPrimary),
                android.graphics.Color.parseColor("#2E7D32")
        );

        // Listen for user swiping down
        swipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() {
            @Override
            public void onRefresh() {
                // Re-calculate the stats from Room DB
                fetchMetricsFromGateway();
            }
        });

        textTotalScanned = findViewById(R.id.textTotalScanned);
        textSafeApps = findViewById(R.id.textSafeApps);
        textThreatsFound = findViewById(R.id.textThreatsFound);

        cardActiveScan = findViewById(R.id.cardActiveScan);
        textScanningAppName = findViewById(R.id.textScanningAppName);
        textScanStatusLog = findViewById(R.id.textScanStatusLog);

        cardCompletedScans = findViewById(R.id.cardCompletedScans);
        textCompletedTitle = findViewById(R.id.textCompletedTitle);

        btnOpenAppList = findViewById(R.id.btnOpenAppList);

        // 1. Navigation to the full App List
        btnOpenAppList.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, MainActivity.class);
            startActivity(intent);
        });

        // 2. Navigation back to the Progress Page when the Active Scan card is clicked
        cardActiveScan.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, ProgressActivity.class);
            startActivity(intent);
        });

        cardCompletedScans.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, ProgressActivity.class);
            startActivity(intent);
        });

        // 3. Observe the ScanManager to show/hide the Active Scan card dynamically
        ScanManager.getInstance().getActiveScans().observe(this, new Observer<List<ScanJob>>() {
            @Override
            public void onChanged(List<ScanJob> scanJobs) {
                int activeCount = 0;
                int completedCount = 0;

                // Count the jobs
                for (ScanJob job : scanJobs) {
                    if (!job.isComplete()) {
                        activeCount++;
                    } else {
                        completedCount++;
                    }
                }

                // Handle the Active Card
                if (activeCount > 0) {
                    cardActiveScan.setVisibility(View.VISIBLE);
                    textScanningAppName.setText(activeCount + " Active scan" + (activeCount > 1 ? "s" : ""));
                } else {
                    cardActiveScan.setVisibility(View.GONE);
                }

                // Handle the Completed Card
                if (completedCount > 0) {
                    cardCompletedScans.setVisibility(View.VISIBLE);
                    textCompletedTitle.setText(completedCount + " Report" + (completedCount > 1 ? "s" : "") + " ready");
                } else {
                    cardCompletedScans.setVisibility(View.GONE);
                }
            }
        });

        scanHistoryDao = AppDatabase.getDatabase(this).scanHistoryDao();
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

    //    private void fetchMetricsFromGateway() {
//        executorService.execute(() -> {
//            try {
//                String jsonResponse = apiClient.getReportsSummary();
//                JSONObject json = new JSONObject(jsonResponse);
//
//                int totalScanned = json.getInt("totalScanned");
//                int safeCount = json.getInt("safeCount");
//                int suspiciousCount = json.getInt("suspiciousCount");
//
//                runOnUiThread(() -> updateDashboardUI(totalScanned, safeCount, suspiciousCount));
//
//            } catch (Exception e) {
//                e.printStackTrace();
//                runOnUiThread(() -> updateDashboardUI(0, 0, 0));
//            }
//        });
//    }
    private void fetchMetricsFromGateway() {
        // Rename this method to loadLocalMetrics() since we aren't hitting the Gateway anymore!
        executorService.execute(() -> {
            try {
                // Instantly pull the exact numbers from the local SQLite database
                int totalScanned = scanHistoryDao.getTotalScans();
                int safeCount = scanHistoryDao.getSafeCount();
                int suspiciousCount = scanHistoryDao.getSuspiciousCount();

                // Push exact numbers to the UI
                runOnUiThread(() -> updateDashboardUI(totalScanned, safeCount, suspiciousCount));

            } catch (Exception e) {
                System.out.println(e.getMessage());
                runOnUiThread(() -> updateDashboardUI(0, 0, 0));
            }
        });
    }

    private void updateDashboardUI(int totalScanned, int safeCount, int suspiciousCount) {
        textTotalScanned.setText(String.valueOf(totalScanned));
        textSafeApps.setText(String.valueOf(safeCount));
        textThreatsFound.setText(String.valueOf(suspiciousCount));

        if (swipeRefreshLayout != null && swipeRefreshLayout.isRefreshing()) {
            swipeRefreshLayout.setRefreshing(false);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
}