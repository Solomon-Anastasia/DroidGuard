package com.security.droidguard.utils;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import androidx.core.app.NotificationCompat;

import com.security.droidguard.R;
import com.security.droidguard.ui.activity.ReportActivity;

public class NotificationHelper {
    private static final String CHANNEL_ID = "scan_results_channel";
    private static final String CHANNEL_NAME = "DroidGuard scan results";

    public static void showScanCompleteNotification(
            Context context,
            String appName,
            String verdict,
            String jsonReport
    ) {
        NotificationManager notificationManager = 
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
        );
        channel.setDescription("Notifications for completed APK scans");
        notificationManager.createNotificationChannel(channel);

        // Open activity when the notification is tapped
        Intent intent = new Intent(context, ReportActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);

        intent.putExtra("APP_NAME", appName);
        intent.putExtra("JSON_REPORT", jsonReport);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                appName.hashCode(),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        String contentText = "clean".equalsIgnoreCase(verdict)
                ? context.getString(R.string.scan_completed_no_threats_detected)
                : context.getString(R.string.attention_suspicious_behaviors_detected);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(context.getString(R.string.analysis_finished) + appName)
                .setContentText(contentText)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true);

        notificationManager.notify(appName.hashCode(), builder.build());
    }
}