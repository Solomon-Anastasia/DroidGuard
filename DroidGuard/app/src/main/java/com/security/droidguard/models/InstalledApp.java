package com.security.droidguard.models;

import android.graphics.drawable.Drawable;

public class InstalledApp {
    private String appName;
    private String packageName;
    private String apkPath;
    private Drawable icon;

    public InstalledApp(String appName, String packageName, String apkPath, Drawable icon) {
        this.appName = appName;
        this.packageName = packageName;
        this.apkPath = apkPath;
        this.icon = icon;
    }

    public String getAppName() {
        return appName;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getApkPath() {
        return apkPath;
    }

    public Drawable getIcon() {
        return icon;
    }
}
