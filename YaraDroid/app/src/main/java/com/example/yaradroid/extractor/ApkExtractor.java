package com.example.yaradroid.extractor;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;

import com.example.yaradroid.models.InstalledApp;

import java.util.ArrayList;
import java.util.List;

public class ApkExtractor {
    public static List<InstalledApp> getUserApps(Context context) {
        List<InstalledApp> appList = new ArrayList<>();
        PackageManager pm = context.getPackageManager();

        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);

        for (ApplicationInfo appInfo : packages) {
            boolean isSystemApp = (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;

            if (!isSystemApp) {
                String appName = pm.getApplicationLabel(appInfo).toString();
                String packageName = appInfo.packageName;
                String apkPath = appInfo.publicSourceDir;
                Drawable icon = pm.getApplicationIcon(appInfo);

                appList.add(new InstalledApp(appName, packageName, apkPath, icon));
            }
        }
        return appList;
    }
}