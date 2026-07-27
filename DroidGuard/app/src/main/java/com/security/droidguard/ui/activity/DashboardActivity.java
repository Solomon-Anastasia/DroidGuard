package com.security.droidguard.ui.activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.os.LocaleListCompat;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.color.MaterialColors;
import com.security.droidguard.MainActivity;
import com.security.droidguard.R;
import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.database.ScanHistoryDao;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ScanManager;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DashboardActivity extends AppCompatActivity {
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    private SwipeRefreshLayout swipeRefreshLayout;
    private MaterialCardView cardActiveScan;
    private MaterialCardView cardCompletedScans;
    private TextView textTotalScanned;
    private TextView textSafeApps;
    private TextView textThreatsFound;
    private TextView textScanningAppName;
    private TextView textCompletedTitle;

    private ScanHistoryDao scanHistoryDao;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);
        ScanManager.getInstance().init(getApplicationContext());

        MaterialButton btnOpenAppList = findViewById(R.id.btnOpenAppList);
        btnOpenAppList.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, MainActivity.class);
            startActivity(intent);
        });

        MaterialButton btnLanguageToggle = findViewById(R.id.btnLanguageToggle);
        btnLanguageToggle.setOnClickListener(v -> {
            String currentLocale = getResources()
                    .getConfiguration()
                    .getLocales()
                    .get(0)
                    .getLanguage();

            String targetLocale = currentLocale.equals("ro") ? "en" : "ro";
            AppCompatDelegate.setApplicationLocales(
                    LocaleListCompat.forLanguageTags(targetLocale)
            );
        });

        swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout);
        swipeRefreshLayout.setColorSchemeColors(
                MaterialColors.getColor(
                        swipeRefreshLayout,
                        androidx.appcompat.R.attr.colorPrimary
                ),
                android.graphics.Color.parseColor("#2E7D32")
        );
        swipeRefreshLayout.setOnRefreshListener(this::loadLocalMetrics);

        textTotalScanned = findViewById(R.id.textTotalScanned);
        textSafeApps = findViewById(R.id.textSafeApps);
        textThreatsFound = findViewById(R.id.textThreatsFound);
        cardActiveScan = findViewById(R.id.cardActiveScan);
        textScanningAppName = findViewById(R.id.textScanningAppName);
        cardCompletedScans = findViewById(R.id.cardCompletedScans);
        textCompletedTitle = findViewById(R.id.textCompletedTitle);

        cardActiveScan.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, ProgressActivity.class);
            startActivity(intent);
        });

        cardCompletedScans.setOnClickListener(v -> {
            Intent intent = new Intent(DashboardActivity.this, ProgressActivity.class);
            startActivity(intent);
        });

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

            if (activeCount > 0) {
                cardActiveScan.setVisibility(View.VISIBLE);
                textScanningAppName.setText(getString(R.string.active_scans_count, activeCount));
            } else {
                cardActiveScan.setVisibility(View.GONE);
            }

            if (completedCount > 0) {
                cardCompletedScans.setVisibility(View.VISIBLE);
                textCompletedTitle.setText(getString(R.string.reports_ready_count, completedCount));
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