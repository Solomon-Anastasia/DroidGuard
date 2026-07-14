package com.security.droidguard;

import android.content.Intent;
import android.os.Bundle;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.extractor.ApkExtractor;
import com.security.droidguard.models.InstalledApp;
import com.security.droidguard.network.AnalysisProxy;
import com.security.droidguard.network.ScanManager;
import com.security.droidguard.ui.adapter.AppListAdapter;
import com.security.droidguard.ui.activity.ProgressActivity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private RecyclerView recyclerView;
    private AppListAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        MaterialToolbar toolbar = findViewById(R.id.mainToolbar);
        setSupportActionBar(toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        recyclerView = findViewById(R.id.recyclerView);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        List<InstalledApp> allInstalledApps = ApkExtractor.getUserApps(this);

        Executors.newSingleThreadExecutor().execute(() -> {
            List<String> alreadyScannedApps = AppDatabase.getDatabase(MainActivity.this)
                    .scanHistoryDao()
                    .getScannedAppNames();

            List<InstalledApp> appsToShow = new ArrayList<>();

            for (InstalledApp app : allInstalledApps) {
                if (!alreadyScannedApps.contains(app.getAppName())) {
                    appsToShow.add(app);
                }
            }

            runOnUiThread(() -> {
                adapter = new AppListAdapter(appsToShow, app -> {

                    new MaterialAlertDialogBuilder(MainActivity.this)
                            .setTitle("Scan application?")
                            .setMessage("Do you want to send " + app.getAppName() + " to the Gateway for malware analysis?")
                            .setPositiveButton("Start scan", (dialog, which) -> {
                                ScanManager.getInstance().startScan(app.getApkPath(), app.getAppName());
                                Intent intent = new Intent(MainActivity.this, ProgressActivity.class);
                                startActivity(intent);
                            })
                            .setNegativeButton("Cancel", (dialog, which) -> dialog.dismiss())
                            .show();
                });

                recyclerView.setAdapter(adapter);
            });
        });
    }
}