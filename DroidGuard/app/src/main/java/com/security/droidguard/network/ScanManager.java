package com.security.droidguard.network;

import android.content.Context;
import android.content.Intent;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.security.droidguard.R;
import com.security.droidguard.database.AppDatabase;
import com.security.droidguard.database.LocalScanRecord;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.ui.activity.ProgressActivity;
import com.security.droidguard.utils.NotificationHelper;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ScanManager {
    // Container for observer
    private final MutableLiveData<List<ScanJob>> activeScansLiveData;
    private final Map<String, AnalysisHandle> activeHandles;
    private final ExecutorService networkExecutor = Executors.newCachedThreadPool();
    private final ExecutorService dbExecutor = Executors.newSingleThreadExecutor();
    private Context appContext;

    private final List<ScanJob> currentScans;
    private AppDatabase database;
    private AnalysisProxy analysisProxy;
    private ApiClient apiClient;
    private static ScanManager instance;

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

            if (this.apiClient == null) {
                this.apiClient = new ApiClient();
            }
        }

        if (this.database == null) {
            this.database = AppDatabase.getDatabase(context);

            dbExecutor.execute(() -> {
                List<LocalScanRecord> history = database.scanHistoryDao().getAllHistory();

                for (LocalScanRecord record : history) {
                    if ("PENDING".equals(record.verdict) && record.jobId != null) {
                        ScanJob recoveringJob = new ScanJob(record.appName, R.string.status_recovering_scan);
                        currentScans.add(recoveringJob);

                        AnalysisHandle handle = analysisProxy.resumePolling(
                                record.jobId, record.scanTimestamp, new AnalysisCallback() {
                                    @Override
                                    public void onProgress(String status) {
                                        // Guard against trailing progress updates after completion
                                        if (recoveringJob.isComplete()) return;

                                        recoveringJob.setStatusLog(status);
                                        activeScansLiveData.postValue(new ArrayList<>(currentScans));
                                    }

                                    @Override
                                    public void onSuccess(String jsonReport) {
                                        activeHandles.remove(record.appName);
                                        recoveringJob.setStatusResId(R.string.status_completed_report);
                                        recoveringJob.setComplete(true);
                                        recoveringJob.setJsonReport(jsonReport);
                                        activeScansLiveData.postValue(new ArrayList<>(currentScans));

                                        dbExecutor.execute(() -> {
                                            String finalVerdict = "safe";

                                            try {
                                                JSONObject json = new JSONObject(jsonReport);

                                                if (json.has("verdict"))
                                                    finalVerdict = json.getString("verdict");
                                            } catch (Exception e) {
                                                System.out.println(e.getMessage());
                                            }

                                            database.scanHistoryDao().deleteByAppName(record.appName);
                                            LocalScanRecord newRecord = new LocalScanRecord(
                                                    record.appName,
                                                    "com.security.droidguard",
                                                    jsonReport,
                                                    finalVerdict,
                                                    System.currentTimeMillis()
                                            );
                                            database.scanHistoryDao().insert(newRecord);
                                            if (!ProgressActivity.isVisible) {
                                                NotificationHelper.showScanCompleteNotification(
                                                        appContext,
                                                        record.appName,
                                                        finalVerdict,
                                                        jsonReport
                                                );
                                            }
                                        });
                                    }

                                    @Override
                                    public void onError(String error) {
                                        activeHandles.remove(record.appName);
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

        Intent serviceIntent = new Intent(appContext, ScanForegroundService.class);
        serviceIntent.setAction(ScanForegroundService.ACTION_START_SERVICE);
        serviceIntent.putExtra(ScanForegroundService.EXTRA_APP_NAME, appName);
        appContext.startForegroundService(serviceIntent);

        AnalysisHandle handle = analysisProxy.startAnalysis(
                apkPath, appName, new AnalysisCallback() {
                    @Override
                    public void onProgress(String status) {
                        if (newJob.isComplete())
                            return;

                        if (status.startsWith("JOB_ID_ATTACHED:")) {
                            String savedJobId = status.split(":")[1];

                            dbExecutor.execute(() -> {
                                database.scanHistoryDao().deleteByAppName(appName);
                                LocalScanRecord record = new LocalScanRecord(
                                        appName,
                                        "com.security.droidguard",
                                        "{}",
                                        "PENDING",
                                        System.currentTimeMillis()
                                );

                                record.jobId = savedJobId;
                                database.scanHistoryDao().insert(record);
                            });
                        } else {
                            try {
                                JSONObject json = new JSONObject(status);
                                String currentStatus = json.optString("status");

                                if ("IN_PROGRESS".equals(currentStatus)) {
                                    if (newJob.getStartTime() == 0) {
                                        newJob.startTimer();
                                    }
                                    newJob.setStatusLog(String.valueOf(R.string.status_analyzing));
                                }
                            } catch (Exception e) {
                                newJob.setStatusLog(status);
                            }

                            activeScansLiveData.postValue(new ArrayList<>(currentScans));
                        }
                    }

                    @Override
                    public void onSuccess(String jsonReport) {
                        activeHandles.remove(appName);
                        stopForegroundService();

                        newJob.setStatusResId(R.string.status_completed_report);
                        newJob.setComplete(true);
                        newJob.setJsonReport(jsonReport);
                        activeScansLiveData.postValue(new ArrayList<>(currentScans));

                        dbExecutor.execute(() -> {
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
                            if (!ProgressActivity.isVisible) {
                                NotificationHelper.showScanCompleteNotification(
                                        appContext,
                                        appName,
                                        verdict,
                                        jsonReport
                                );
                            }
                        });
                    }

                    @Override
                    public void onError(String error) {
                        activeHandles.remove(appName);
                        stopForegroundService();

                        newJob.setStatusResId(R.string.status_failed, error);
                        newJob.setComplete(true);
                        activeScansLiveData.postValue(new ArrayList<>(currentScans));

                        cleanupFailedScan(appName);
                    }
                });

        activeHandles.put(appName, handle);
    }

    public void syncActiveScans() {
        networkExecutor.execute(() -> {
            for (ScanJob job : currentScans) {
                if (job.isComplete())
                    continue;

                AnalysisHandle handle = activeHandles.get(job.getAppName());
                if (handle != null && handle.getJobId() != null) {
                    try {
                        String statusResponse = apiClient.pollStatus(handle.getJobId());
                        JSONObject jsonResponse = new JSONObject(statusResponse);
                        String status = jsonResponse.optString("status", "PENDING");

                        if ("COMPLETED".equals(status)) {
                            JSONObject yaraReportObj = jsonResponse.optJSONObject("yaraReport");
                            String jsonReport = (yaraReportObj != null) ? yaraReportObj.toString() : "{}";

                            job.setStatusResId(R.string.status_completed_report);
                            job.setComplete(true);
                            job.setJsonReport(jsonReport);

                            activeHandles.remove(job.getAppName());
                            stopForegroundService();

                            dbExecutor.execute(() -> {
                                String verdict = "safe";
                                try {
                                    JSONObject reportObj = new JSONObject(jsonReport);
                                    if (reportObj.has("verdict")) {
                                        verdict = reportObj.getString("verdict");
                                    }
                                } catch (Exception e) {
                                    System.out.println(e.getMessage());
                                }

                                database.scanHistoryDao().deleteByAppName(job.getAppName());
                                LocalScanRecord newRecord = new LocalScanRecord(
                                        job.getAppName(),
                                        "com.security.droidguard",
                                        jsonReport,
                                        verdict,
                                        System.currentTimeMillis()
                                );
                                database.scanHistoryDao().insert(newRecord);
                                if (!ProgressActivity.isVisible) {
                                    NotificationHelper.showScanCompleteNotification(
                                            appContext,
                                            job.getAppName(),
                                            verdict,
                                            jsonReport
                                    );
                                }
                            });

                        } else if ("FAILED".equals(status) || "ABORTED".equals(status)) {
                            job.setStatusResId(R.string.status_failed, "Server error");
                            job.setComplete(true);
                            activeHandles.remove(job.getAppName());
                            stopForegroundService();

                            cleanupFailedScan(job.getAppName());
                        }

                    } catch (Exception e) {
                        System.out.println(e.getMessage());
                    }
                }
            }

            activeScansLiveData.postValue(new ArrayList<>(currentScans));
        });
    }

    private void cleanupFailedScan(String appName) {
        dbExecutor.execute(() -> {
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
            stopForegroundService();
        }

        for (int i = 0; i < currentScans.size(); i++) {
            ScanJob job = currentScans.get(i);

            if (job.getAppName().equals(appName) && !job.isComplete()) {
                currentScans.remove(i);
                activeScansLiveData.postValue(new ArrayList<>(currentScans));

                dbExecutor.execute(() ->
                        database.scanHistoryDao().deleteByAppName(appName));
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

        for (int i = 0; i < currentScans.size(); i++) {
            if (currentScans.get(i).getAppName().equals(appNameToDelete)) {
                currentScans.remove(i);
                break;
            }
        }

        activeScansLiveData.setValue(new ArrayList<>(currentScans));
        dbExecutor.execute(() ->
                AppDatabase.getDatabase(context).scanHistoryDao().deleteByAppName(appNameToDelete));
    }

    private void stopForegroundService() {
        if (appContext != null) {
            Intent serviceIntent = new Intent(appContext, ScanForegroundService.class);
            serviceIntent.setAction(ScanForegroundService.ACTION_STOP_SERVICE);
            appContext.startService(serviceIntent);
        }
    }
}