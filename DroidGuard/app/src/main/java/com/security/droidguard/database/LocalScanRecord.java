package com.security.droidguard.database;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "scan_history")
public class LocalScanRecord {
    @PrimaryKey(autoGenerate = true)
    public int id;

    public String appName;
    public String packageName;
    public String jsonReport;
    public String verdict; // "safe", "suspicious", or "malicious"
    public long scanTimestamp;

    public LocalScanRecord(String appName, String packageName, String jsonReport, String verdict, long scanTimestamp) {
        this.appName = appName;
        this.packageName = packageName;
        this.jsonReport = jsonReport;
        this.verdict = verdict;
        this.scanTimestamp = scanTimestamp;
    }
}