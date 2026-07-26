package com.security.droidguard.network;

import android.content.Context;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.security.droidguard.R;
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
    private AnalysisProxy analysisProxy;
    private Context appContext;
    private final java.util.concurrent.ExecutorService dbExecutor = java.util.concurrent.Executors.newSingleThreadExecutor();

    private ScanManager() {
        currentScans = new ArrayList<>();
        activeScansLiveData = new MutableLiveData<>(currentScans);
        activeHandles = new HashMap<>();
    }

    public static synchronized ScanManager getInstance() {
        if (instance == null) {
            instance = new ScanManager();
        }
        return instance;
    }

    public void init(Context context) {
        if (this.appContext == null) {
            this.appContext = context.getApplicationContext();

            if (this.analysisProxy == null) {
                this.analysisProxy = new AnalysisProxy(this.appContext);
            }
        }

        if (this.database == null) {
            this.database = AppDatabase.getDatabase(context);

            Executors.newSingleThreadExecutor().execute(() -> {
                List<LocalScanRecord> history = database.scanHistoryDao().getAllHistory();

                for (LocalScanRecord record : history) {
                    if ("PENDING".equals(record.verdict) && record.jobId != null) {
                        ScanJob recoveringJob = new ScanJob(record.appName, R.string.status_recovering_scan);
                        currentScans.add(recoveringJob);

                        AnalysisHandle handle = analysisProxy.resumePolling(record.jobId, record.scanTimestamp, new AnalysisCallback() {
                            @Override
                            public void onProgress(String status) {
                                // Guard against trailing progress updates after completion
                                if (recoveringJob.isComplete()) return;

                                recoveringJob.setStatusLog(status);
                                activeScansLiveData.postValue(new ArrayList<>(currentScans));
                            }

                            @Override
                            public void onSuccess(String jsonReport) {
                                activeHandles.remove(record.appName); // Clean up handle
                                recoveringJob.setStatusResId(R.string.status_completed_report);
                                recoveringJob.setComplete(true);
                                recoveringJob.setJsonReport(jsonReport);
                                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                                Executors.newSingleThreadExecutor().execute(() -> {
                                    String finalVerdict = "safe";
                                    try {
                                        JSONObject json = new JSONObject(jsonReport);
                                        if (json.has("verdict"))
                                            finalVerdict = json.getString("verdict");
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }

                                    database.scanHistoryDao().deleteByAppName(record.appName);
                                    LocalScanRecord newRecord = new LocalScanRecord(
                                            record.appName, "com.security.droidguard", jsonReport, finalVerdict, System.currentTimeMillis()
                                    );
                                    database.scanHistoryDao().insert(newRecord);
                                });
                            }

                            @Override
                            public void onError(String error) {
                                activeHandles.remove(record.appName); // Clean up handle
                                recoveringJob.setStatusResId(R.string.status_failed, error);
                                recoveringJob.setComplete(true);
                                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                                cleanupFailedScan(record.appName);
                            }
                        });
                        activeHandles.put(record.appName, handle);
                    } else {
                        ScanJob cachedJob = new ScanJob(record.appName, R.string.status_completed_report);
                        cachedJob.setComplete(true);
                        cachedJob.setJsonReport(record.jsonReport);
                        currentScans.add(cachedJob);
                    }
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

        ScanJob newJob = new ScanJob(appName, R.string.status_initializing);
        newJob.setApkPath(apkPath);
        currentScans.add(newJob);
        activeScansLiveData.setValue(new ArrayList<>(currentScans));

        AnalysisHandle handle = analysisProxy.startAnalysis(apkPath, appName, new AnalysisCallback() {
            @Override
            public void onProgress(String status) {
                if (newJob.isComplete()) return;

                if (status.startsWith("JOB_ID_ATTACHED:")) {
                    String savedJobId = status.split(":")[1];

                    dbExecutor.execute(() -> {
                        database.scanHistoryDao().deleteByAppName(appName);

                        LocalScanRecord record = new LocalScanRecord(
                                appName, "com.security.droidguard", "{}", "PENDING", System.currentTimeMillis()
                        );
                        record.jobId = savedJobId;
                        database.scanHistoryDao().insert(record);
                    });
                } else {
                    newJob.setStatusLog(status);
                    activeScansLiveData.postValue(new ArrayList<>(currentScans));
                }
            }

            @Override
            public void onSuccess(String jsonReport) {
                activeHandles.remove(appName);
                newJob.setStatusResId(R.string.status_completed_report);
                newJob.setComplete(true);
                newJob.setJsonReport(jsonReport);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

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

                    database.scanHistoryDao().deleteByAppName(appName);

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
                activeHandles.remove(appName);
                newJob.setStatusResId(R.string.status_failed, error);
                newJob.setComplete(true);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                cleanupFailedScan(appName);
            }
        });

        activeHandles.put(appName, handle);
    }

    private void cleanupFailedScan(String appName) {
        Executors.newSingleThreadExecutor().execute(() -> {
            database.scanHistoryDao().deleteByAppName(appName);

            LocalScanRecord record = new LocalScanRecord(
                    appName,
                    "com.security.droidguard",
                    "{}",
                    "FAILED",
                    System.currentTimeMillis()
            );
            database.scanHistoryDao().insert(record);
        });
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

        for (int i = 0; i < currentScans.size(); i++) {
            ScanJob job = currentScans.get(i);

            if (job.getAppName().equals(appName) && !job.isComplete()) {
                currentScans.remove(i);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                Executors.newSingleThreadExecutor().execute(() -> {
                    database.scanHistoryDao().deleteByAppName(appName);
                });
                break;
            }
        }
    }

    public void deleteScanHistory(Context context, String appNameToDelete, boolean isComplete) {
        if (!isComplete && activeHandles.containsKey(appNameToDelete)) {
            abortActiveScan(appNameToDelete);
            return;
        }

        if (isComplete) {
            activeHandles.remove(appNameToDelete);
        }

        // Remove from list on the main thread
        for (int i = 0; i < currentScans.size(); i++) {
            if (currentScans.get(i).getAppName().equals(appNameToDelete)) {
                currentScans.remove(i);
                break;
            }
        }

        // Force the UI to update synchronously
        activeScansLiveData.setValue(new ArrayList<>(currentScans));

        // Safely perform database work using the shared executor
        dbExecutor.execute(() -> {
            AppDatabase.getDatabase(context).scanHistoryDao().deleteByAppName(appNameToDelete);
        });
    }
}