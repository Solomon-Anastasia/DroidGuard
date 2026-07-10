package com.security.droidguard.ui.activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.security.droidguard.MainActivity;
import com.security.droidguard.R;
import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.database.ScanHistoryDao;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ScanManager;

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

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);

        ScanManager.getInstance().init(getApplicationContext());

        swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout);

        swipeRefreshLayout.setColorSchemeColors(
                com.google.android.material.color.MaterialColors.getColor(swipeRefreshLayout, androidx.appcompat.R.attr.colorPrimary),
                android.graphics.Color.parseColor("#2E7D32")
        );

        // Listen for user swiping down
        swipeRefreshLayout.setOnRefreshListener(this::loadLocalMetrics);

        textTotalScanned = findViewById(R.id.textTotalScanned);
        textSafeApps = findViewById(R.id.textSafeApps);
        textThreatsFound = findViewById(R.id.textThreatsFound);

        cardActiveScan = findViewById(R.id.cardActiveScan);
        textScanningAppName = findViewById(R.id.textScanningAppName);
        textScanStatusLog = findViewById(R.id.textScanStatusLog);

        cardCompletedScans = findViewById(R.id.cardCompletedScans);
        textCompletedTitle = findViewById(R.id.textCompletedTitle);

        btnOpenAppList = findViewById(R.id.btnOpenAppList);

        // Navigation to the full app List
        btnOpenAppList.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, MainActivity.class);
            startActivity(intent);
        });

        // Navigation back to the progress page when the active scan card is clicked
        cardActiveScan.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, ProgressActivity.class);
            startActivity(intent);
        });

        cardCompletedScans.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, ProgressActivity.class);
            startActivity(intent);
        });

        // Observe the ScanManager to show/hide the active scan card dynamically
        ScanManager.getInstance().getActiveScans().observe(this, scanJobs -> {
            int activeCount = 0;
            int completedCount = 0;

            for (ScanJob job : scanJobs) {
                if (!job.isComplete()) {
                    activeCount++;
                } else {
                    completedCount++;
                }
            }

            // Handle the active card
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
        loadLocalMetrics();
    }

    private void loadLocalMetrics() {
        executorService.execute(() -> {
            try {
                int totalScanned = scanHistoryDao.getTotalScans();
                int safeCount = scanHistoryDao.getSafeCount();
                int suspiciousCount = scanHistoryDao.getSuspiciousCount();

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