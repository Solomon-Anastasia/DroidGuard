package com.security.droidguard.models;

public class ScanJob {
    private String appName;
    private String statusLog;
    private boolean isComplete;
    private String jsonReport;

    public ScanJob(String appName, String statusLog) {
        this.appName = appName;
        this.statusLog = statusLog;
        this.isComplete = false;
    }

    public String getAppName() {
        return appName;
    }

    public String getStatusLog() {
        return statusLog;
    }

    public void setStatusLog(String statusLog) {
        this.statusLog = statusLog;
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