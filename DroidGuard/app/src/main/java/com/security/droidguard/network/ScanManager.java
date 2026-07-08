package com.security.droidguard.network;

import android.content.Context;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.database.LocalScanRecord;
import com.security.droidguard.models.ScanJob;

import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

public class ScanManager {
    private static ScanManager instance;
    private final MutableLiveData<List<ScanJob>> activeScansLiveData;
    private final List<ScanJob> currentScans;
    private AppDatabase database;

    // 1. RESTORED: The core network engine field
    private final AnalysisProxy analysisProxy;

    private ScanManager() {
        currentScans = new ArrayList<>();
        activeScansLiveData = new MutableLiveData<>(currentScans);
        // 2. RESTORED: Initialize the proxy engine
        analysisProxy = new AnalysisProxy();
    }

    public static synchronized ScanManager getInstance() {
        if (instance == null) {
            instance = new ScanManager();
        }
        return instance;
    }

    public void init(Context context) {
        if (this.database == null) {
            this.database = AppDatabase.getDatabase(context);

            // Load persistent records from Room into your active UI view on startup
            Executors.newSingleThreadExecutor().execute(() -> {
                List<LocalScanRecord> history = database.scanHistoryDao().getAllHistory();
                for (LocalScanRecord record : history) {
                    ScanJob cachedJob = new ScanJob(record.appName, "Completed. View Report.");
                    cachedJob.setComplete(true);
                    cachedJob.setJsonReport(record.jsonReport);
                    currentScans.add(cachedJob);
                }
                activeScansLiveData.postValue(new ArrayList<>(currentScans));
            });
        }
    }

    public LiveData<List<ScanJob>> getActiveScans() {
        return activeScansLiveData;
    }

    public void startScan(String apkPath, String appName) {
        for (ScanJob job : currentScans) {
            if (job.getAppName().equals(appName)) {
                // The app is already scanning or already completed in this session. Abort!
                return;
            }
        }

        ScanJob newJob = new ScanJob(appName, "Initializing scan...");
        currentScans.add(newJob);
        activeScansLiveData.postValue(new ArrayList<>(currentScans));

        // 3. RESTORED: Un-comment and fully wire the background processing pipeline
        analysisProxy.startAnalysis(apkPath, appName, new AnalysisCallback() {
            @Override
            public void onProgress(String status) {
                newJob.setStatusLog(status);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));
            }

            @Override
            public void onSuccess(String jsonReport) {
                newJob.setStatusLog("Completed. View Report.");
                newJob.setComplete(true);
                newJob.setJsonReport(jsonReport);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                // Save it persistently to Room SQLite so it never vanishes on restart
                Executors.newSingleThreadExecutor().execute(() -> {
                    String verdict = "safe"; // baseline default
                    try {
                        JSONObject json = new JSONObject(jsonReport);
                        if (json.has("verdict")) {
                            verdict = json.getString("verdict");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    LocalScanRecord record = new LocalScanRecord(
                            appName,
                            "com.security.droidguard",
                            jsonReport,
                            verdict,
                            System.currentTimeMillis()
                    );
                    database.scanHistoryDao().insert(record);
                });
            }

            @Override
            public void onError(String error) {
                newJob.setStatusLog("Failed: " + error);
                newJob.setComplete(true);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));
            }
        });
    }

    public void deleteScanHistory(Context context, String appNameToDelete) {
        Executors.newSingleThreadExecutor().execute(() -> {
            // 1. Delete it from the local SQLite database
            AppDatabase.getDatabase(context).scanHistoryDao().deleteByAppName(appNameToDelete);

            // 2. (Optional) If you want to also remove it from the active UI list in ScanManager
            for (int i = 0; i < currentScans.size(); i++) {
                if (currentScans.get(i).getAppName().equals(appNameToDelete)) {
                    currentScans.remove(i);
                    break;
                }
            }
            // Update the LiveData so the ProgressActivity UI refreshes instantly
            activeScansLiveData.postValue(new ArrayList<>(currentScans));
        });
    }

    // Safely stop background threads if needed
    public void shutdown() {
        if (analysisProxy != null) {
            analysisProxy.shutdown();
        }
    }
}