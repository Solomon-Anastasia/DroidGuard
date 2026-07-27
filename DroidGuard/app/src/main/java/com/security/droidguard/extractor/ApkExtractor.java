package com.security.droidguard.extractor;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;

import com.security.droidguard.models.InstalledApp;

import java.util.ArrayList;
import java.util.List;

public class ApkExtractor {
    public static List<InstalledApp> getUserApps(Context context) {
        List<InstalledApp> appList = new ArrayList<>();
        PackageManager packageManager = context.getPackageManager();

        String myPackageName = context.getPackageName();
        List<ApplicationInfo> packages = packageManager.getInstalledApplications(PackageManager.GET_META_DATA);

        for (ApplicationInfo appInfo : packages) {
            boolean isSystemApp = (appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            boolean isUpdatedSystemApp = (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;

            if ((!isSystemApp || isUpdatedSystemApp) && !appInfo.packageName.equals(myPackageName)) {
                String appName = packageManager.getApplicationLabel(appInfo).toString();
                String packageName = appInfo.packageName;
                String apkPath = appInfo.publicSourceDir;
                Drawable icon = packageManager.getApplicationIcon(appInfo);

                appList.add(new InstalledApp(appName, packageName, apkPath, icon));
            }
        }
        return appList;
    }
}