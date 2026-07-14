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
                    if ("PENDING".equals(record.verdict) && record.jobId != null) {
                        // RECOVERY MODE: The app crashed while this was scanning
                        ScanJob recoveringJob = new ScanJob(record.appName, "Recovering scan...");
                        currentScans.add(recoveringJob);

                        AnalysisHandle handle = analysisProxy.resumePolling(record.jobId, record.appName, new AnalysisCallback() {
                            @Override
                            public void onProgress(String status) {
                                recoveringJob.setStatusLog(status);
                                activeScansLiveData.postValue(new ArrayList<>(currentScans));
                            }

                            @Override
                            public void onSuccess(String jsonReport) {
                                recoveringJob.setStatusLog("Completed! View report");
                                recoveringJob.setComplete(true);
                                recoveringJob.setJsonReport(jsonReport);
                                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                                Executors.newSingleThreadExecutor().execute(() -> {
                                    String finalVerdict = "safe";
                                    try {
                                        JSONObject json = new JSONObject(jsonReport);
                                        if (json.has("verdict")) finalVerdict = json.getString("verdict");
                                    } catch (Exception e) { e.printStackTrace(); }

                                    // Erase the PENDING record, insert the COMPLETED record
                                    database.scanHistoryDao().deleteByAppName(record.appName);
                                    LocalScanRecord newRecord = new LocalScanRecord(
                                            record.appName, "com.security.droidguard", jsonReport, finalVerdict, System.currentTimeMillis()
                                    );
                                    database.scanHistoryDao().insert(newRecord);
                                });
                            }

                            @Override
                            public void onError(String error) {
                                recoveringJob.setStatusLog("Failed: " + error);
                                recoveringJob.setComplete(true);
                                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                                // Clean up the stuck pending record on failure
                                Executors.newSingleThreadExecutor().execute(() -> {
                                    database.scanHistoryDao().deleteByAppName(record.appName);
                                });
                            }
                        });
                        activeHandles.put(record.appName, handle);
                    } else {
                        // NORMAL MODE: It's a completed job, load it to the UI
                        ScanJob cachedJob = new ScanJob(record.appName, "Completed! View report");
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

        ScanJob newJob = new ScanJob(appName, "Initializing scan...");
        currentScans.add(newJob);
        activeScansLiveData.postValue(new ArrayList<>(currentScans));

        AnalysisHandle handle = analysisProxy.startAnalysis(apkPath, appName, new AnalysisCallback() {
            @Override
            public void onProgress(String status) {
                // Intercept the Job ID to save it to Room
                if (status.startsWith("JOB_ID_ATTACHED:")) {
                    String savedJobId = status.split(":")[1];
                    Executors.newSingleThreadExecutor().execute(() -> {
                        // Clear any old failed attempts first
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
                newJob.setStatusLog("Completed! View report");
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

                    // Erase the PENDING record before saving the final one
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
                newJob.setStatusLog("Failed: " + error);
                newJob.setComplete(true);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                // Clean up the stuck pending record on failure
                Executors.newSingleThreadExecutor().execute(() -> {
                    database.scanHistoryDao().deleteByAppName(appName);
                });
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

        for (int i = 0; i < currentScans.size(); i++) {
            ScanJob job = currentScans.get(i);

            if (job.getAppName().equals(appName) && !job.isComplete()) {
                currentScans.remove(i);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                // Erase the aborted scan from Room
                Executors.newSingleThreadExecutor().execute(() -> {
                    database.scanHistoryDao().deleteByAppName(appName);
                });
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