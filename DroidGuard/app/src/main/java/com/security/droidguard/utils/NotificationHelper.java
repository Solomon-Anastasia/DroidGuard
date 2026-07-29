package com.security.droidguard.utils;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import androidx.core.app.NotificationCompat;

import com.security.droidguard.R;
import com.security.droidguard.ui.activity.ReportActivity;
import com.security.droidguard.ui.activity.DashboardActivity;

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

        Intent parentIntent = new Intent(context, DashboardActivity.class);
        parentIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);

        Intent reportIntent = new Intent(context, ReportActivity.class);
        reportIntent.putExtra("APP_NAME", appName);
        reportIntent.putExtra("JSON_REPORT", jsonReport);

        Intent[] intents = { parentIntent, reportIntent };

        PendingIntent pendingIntent = PendingIntent.getActivities(
                context,
                Math.abs(appName.hashCode()),
                intents,
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

        notificationManager.notify(Math.abs(appName.hashCode()), builder.build());
    }
}