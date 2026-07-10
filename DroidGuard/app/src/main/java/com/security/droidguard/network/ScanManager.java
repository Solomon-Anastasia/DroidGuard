package com.security.droidguard.network;

import android.content.Context;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.database.LocalScanRecord;
import com.security.droidguard.models.ScanJob;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public class ScanManager {
    private static ScanManager instance;
    private final MutableLiveData<List<ScanJob>> activeScansLiveData;
    private final Map<String, AnalysisHandle> activeHandles;
    private final List<ScanJob> currentScans;
    private AppDatabase database;
    private final AnalysisProxy analysisProxy;

    private ScanManager() {
        currentScans = new ArrayList<>();
        activeScansLiveData = new MutableLiveData<>(currentScans);
        analysisProxy = new AnalysisProxy();
        activeHandles = new HashMap<>();
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

            // Load persistent records from room into active UI view on startup
            Executors.newSingleThreadExecutor().execute(() -> {
                List<LocalScanRecord> history = database.scanHistoryDao().getAllHistory();

                for (LocalScanRecord record : history) {
                    ScanJob cachedJob = new ScanJob(record.appName, "Completed! View report");
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
                return;
            }
        }

        ScanJob newJob = new ScanJob(appName, "Initializing scan...");
        currentScans.add(newJob);
        activeScansLiveData.postValue(new ArrayList<>(currentScans));

        AnalysisHandle handle = analysisProxy.startAnalysis(apkPath, appName, new AnalysisCallback() {
            @Override
            public void onProgress(String status) {
                newJob.setStatusLog(status);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));
            }

            @Override
            public void onSuccess(String jsonReport) {
                newJob.setStatusLog("Completed! View report");
                newJob.setComplete(true);
                newJob.setJsonReport(jsonReport);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                // Save it persistently to Room SQLite
                Executors.newSingleThreadExecutor().execute(() -> {
                    String verdict = "safe";

                    try {
                        JSONObject json = new JSONObject(jsonReport);
                        if (json.has("verdict")) {
                            verdict = json.getString("verdict");
                        }
                    } catch (Exception e) {
                        System.out.println(e.getMessage());
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

        activeHandles.put(appName, handle);
    }

    public void abortActiveScan(String appName) {
        AnalysisHandle handle = activeHandles.get(appName);
        if (handle != null) {
            handle.cancel();

            if (handle.getJobId() != null) {
                analysisProxy.cancelAnalysisOnServer(handle.getJobId());
            }

            activeHandles.remove(appName);
        }

        // Remove UI part
        for (int i = 0; i < currentScans.size(); i++) {
            ScanJob job = currentScans.get(i);

            if (job.getAppName().equals(appName) && !job.isComplete()) {
                currentScans.remove(i);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));
                break;
            }
        }
    }

    public void deleteScanHistory(Context context, String appNameToDelete) {
        Executors.newSingleThreadExecutor().execute(() -> {
            AppDatabase.getDatabase(context).scanHistoryDao().deleteByAppName(appNameToDelete);

            for (int i = 0; i < currentScans.size(); i++) {
                if (currentScans.get(i).getAppName().equals(appNameToDelete)) {
                    currentScans.remove(i);
                    break;
                }
            }

            activeScansLiveData.postValue(new ArrayList<>(currentScans));
        });
    }
}