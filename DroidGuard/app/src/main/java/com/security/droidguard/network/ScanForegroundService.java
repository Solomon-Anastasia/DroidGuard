package com.security.droidguard.network;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.security.droidguard.R;
import com.security.droidguard.ui.activity.ProgressActivity;

public class ScanForegroundService extends Service {
    public static final String ACTION_START_SERVICE = "START_SCAN_SERVICE";
    public static final String ACTION_STOP_SERVICE = "STOP_SCAN_SERVICE";
    public static final String EXTRA_APP_NAME = "APP_NAME";

    private static final String CHANNEL_ID = "scan_progress_channel";
    private static final int NOTIFICATION_ID = 1001;

    private int activeScanCount = 0;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            String action = intent.getAction();

            if (ACTION_START_SERVICE.equals(action)) {
                activeScanCount++;
                String appName = intent.getStringExtra(EXTRA_APP_NAME);
                startForegroundWithNotification(appName);
            } else if (ACTION_STOP_SERVICE.equals(action)) {
                activeScanCount--;

                // Stop the service if no other scans are running
                if (activeScanCount <= 0) {
                    stopForeground(true);
                    stopSelf();
                } else {
                    startForegroundWithNotification(String.valueOf(activeScanCount));
                }
            }
        }

        return START_NOT_STICKY;
    }

    private void startForegroundWithNotification(String targetName) {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);

        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                getString(R.string.active_scans_notification),
                NotificationManager.IMPORTANCE_LOW
        );
        manager.createNotificationChannel(channel);

        Intent openAppIntent = new Intent(this, ProgressActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, openAppIntent, PendingIntent.FLAG_IMMUTABLE
        );

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("DroidGuard")
                .setContentText(
                        getString(R.string.scanning_notification) +
                                (targetName != null ?
                                        targetName : getString(R.string.multiple_apps_notification))
                ).setSmallIcon(R.mipmap.ic_launcher)
                .setContentIntent(pendingIntent)
                .setOngoing(true) // Prevents the user from swiping it away
                .build();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null; // We are not binding this service to UI components
    }
}