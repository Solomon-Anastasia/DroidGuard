package com.security.droidguard.models;

import android.content.Context;

public class ScanJob {
    private String appName;
    private String apkPath;
    private String statusArg = null;
    private String rawStatusLog = null;
    private String jsonReport;

    // Keep track of the one particular object when translating
    private int statusResId;
    private boolean isComplete;

    public ScanJob(String appName, int statusResId) {
        this.appName = appName;
        this.statusResId = statusResId;
        this.isComplete = false;
    }

    public String getApkPath() {
        return apkPath;
    }

    public void setApkPath(String apkPath) {
        this.apkPath = apkPath;
    }

    public String getLocalizedStatus(Context context) {
        if (statusResId != 0) {
            if (statusArg != null) {
                return context.getString(statusResId, statusArg);
            }
            return context.getString(statusResId);
        }

        // Report comes from gateway in json file, not all can be translated
        if (rawStatusLog != null) {
            int resId = context.getResources().getIdentifier(rawStatusLog, "string", context.getPackageName());
            if (resId != 0) {
                return context.getString(resId);
            }
            return rawStatusLog;
        }

        return "";
    }

    public String getAppName() {
        return appName;
    }

    public void setStatusResId(int statusResId) {
        this.statusResId = statusResId;
        this.rawStatusLog = null;
        this.statusArg = null;
    }

    public void setStatusResId(int statusResId, String formatArg) {
        this.statusResId = statusResId;
        this.statusArg = formatArg;
        this.rawStatusLog = null;
    }

    public void setStatusLog(String rawStatusLog) {
        this.rawStatusLog = rawStatusLog;
        this.statusResId = 0;
        this.statusArg = null;
    }

    public boolean isComplete() {
        return isComplete;
    }

    public void setComplete(boolean complete) {
        isComplete = complete;
    }

    public String getJsonReport() {
        return jsonReport;
    }

    public void setJsonReport(String jsonReport) {
        this.jsonReport = jsonReport;
    }
}