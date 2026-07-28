package com.security.droidguard.database;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.Query;

import java.util.List;

@Dao
public interface ScanHistoryDao {
    @Insert
    void insert(LocalScanRecord record);

    @Query("SELECT COUNT(*) FROM scan_history WHERE verdict NOT IN ('PENDING', 'FAILED')")
    int getTotalScans();

    @Query("SELECT COUNT(*) FROM scan_history WHERE verdict = 'safe' OR verdict = 'clean'")
    int getSafeCount();

    @Query("SELECT COUNT(*) FROM scan_history WHERE verdict IN ('suspicious', 'malicious')")
    int getSuspiciousCount();

    @Query("SELECT * FROM scan_history ORDER BY scanTimestamp DESC")
    List<LocalScanRecord> getAllHistory();

    @Query("SELECT appName FROM scan_history")
    List<String> getScannedAppNames();

    @Query("DELETE FROM scan_history WHERE appName = :appName")
    void deleteByAppName(String appName);
}