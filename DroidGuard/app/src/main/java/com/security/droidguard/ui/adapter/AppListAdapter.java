package com.security.droidguard.ui.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.security.droidguard.R;
import com.security.droidguard.models.InstalledApp;
import com.security.droidguard.ui.OnAppClickListener;

import java.util.ArrayList;
import java.util.List;

public class AppListAdapter extends RecyclerView.Adapter<AppListAdapter.AppViewHolder> {

    private List<InstalledApp> appList;
    private final List<InstalledApp> originalAppList;
    private final OnAppClickListener listener;

    public AppListAdapter(List<InstalledApp> appList, OnAppClickListener listener) {
        this.appList = appList;
        this.originalAppList = new ArrayList<>(appList);
        this.listener = listener;
    }

    public void filter(String text) {
        List<InstalledApp> filteredList = new ArrayList<>();

        if (text == null || text.trim().isEmpty()) {
            filteredList.addAll(originalAppList);
        } else {
            String filterPattern = text.toLowerCase().trim();
            for (InstalledApp app : originalAppList) {
                if (app.getAppName().toLowerCase().contains(filterPattern)) {
                    filteredList.add(app);
                }
            }
        }

        this.appList = filteredList;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public AppViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_installed_app, parent, false);
        return new AppViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull AppViewHolder holder, int position) {
        InstalledApp app = appList.get(position);
        holder.appNameText.setText(app.getAppName());
        holder.packageNameText.setText(app.getPackageName());
        holder.appIcon.setImageDrawable(app.getIcon());

        holder.itemView.setOnClickListener(v -> listener.onAppClick(app));
    }

    @Override
    public int getItemCount() {
        return appList.size();
    }

    public static class AppViewHolder extends RecyclerView.ViewHolder {
        ImageView appIcon;
        TextView appNameText;
        TextView packageNameText;

        public AppViewHolder(@NonNull View itemView) {
            super(itemView);

            appIcon = itemView.findViewById(R.id.appIcon);
            appNameText = itemView.findViewById(R.id.appNameText);
            packageNameText = itemView.findViewById(R.id.packageNameText);
        }
    }
}