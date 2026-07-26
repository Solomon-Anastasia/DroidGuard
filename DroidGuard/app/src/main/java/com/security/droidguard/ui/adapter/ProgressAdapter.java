package com.security.droidguard.ui.adapter;

import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.security.droidguard.R;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ScanManager;
import com.security.droidguard.ui.activity.ReportActivity;

import java.util.ArrayList;
import java.util.List;

public class ProgressAdapter extends RecyclerView.Adapter<ProgressAdapter.ProgressViewHolder> {
    private List<ScanJob> scanJobs = new ArrayList<>();
    private List<ScanJob> scanJobsFull = new ArrayList<>();
    private String currentQuery = "";

    public void updateData(List<ScanJob> newJobs) {
        this.scanJobsFull = new ArrayList<>(newJobs);
        filter(currentQuery);
    }

    public void filter(String query) {
        this.currentQuery = (query != null) ? query : "";
        scanJobs.clear();

        if (currentQuery.trim().isEmpty()) {
            scanJobs.addAll(scanJobsFull);
        } else {
            String filterPattern = currentQuery.toLowerCase().trim();
            for (ScanJob job : scanJobsFull) {
                if (job.getAppName() != null && job.getAppName().toLowerCase().contains(filterPattern)) {
                    scanJobs.add(job);
                }
            }
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ProgressViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_scan_progress, parent, false);

        return new ProgressViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ProgressViewHolder holder, int position) {
        ScanJob job = scanJobs.get(position);

        holder.textAppName.setText(job.getAppName());
        holder.textStatusLog.setText(job.getLocalizedStatus(holder.itemView.getContext()));

        if (job.isComplete()) {
            holder.progressSpinner.setVisibility(View.GONE);
            holder.iconComplete.setVisibility(View.VISIBLE);
            holder.btnCancelScan.setVisibility(android.view.View.GONE);
        } else {
            holder.progressSpinner.setVisibility(View.VISIBLE);
            holder.iconComplete.setVisibility(View.GONE);
            holder.btnCancelScan.setVisibility(android.view.View.VISIBLE);
        }

        // Tap
        holder.itemView.setOnClickListener(v -> {
            // A failed scan is complete but has no generated report
            boolean isFailed = job.isComplete() && job.getJsonReport() == null;

            if (isFailed) {
                // Tap on a failed scan
                new MaterialAlertDialogBuilder(v.getContext())
                        .setTitle(v.getContext().getString(R.string.retry_scan_title))
                        .setMessage(v.getContext().getString(R.string.retry_scan_message, job.getAppName()))
                        .setPositiveButton(v.getContext().getString(R.string.action_retry), (dialog, which) -> {
                            // Clear the failed history first
                            ScanManager.getInstance().deleteScanHistory(
                                    v.getContext(),
                                    job.getAppName(),
                                    job.isComplete()
                            );

                            // Trigger the scan again
                            String savedApkPath = job.getApkPath();
                            if (savedApkPath != null) {
                                ScanManager.getInstance().startScan(savedApkPath, job.getAppName());
                            } else {
                                Toast.makeText(
                                        v.getContext(),
                                        "APK path unavailable. Please initiate a new scan from the apps list.",
                                        Toast.LENGTH_LONG
                                ).show();
                            }
                        })
                        .setNeutralButton(v.getContext().getString(R.string.action_delete), (dialog, which) -> {
                            ScanManager.getInstance().deleteScanHistory(
                                    v.getContext(),
                                    job.getAppName(),
                                    job.isComplete()
                            );
                        })
                        .setNegativeButton(
                                v.getContext().getString(R.string.action_cancel),
                                null
                        )
                        .show();
            } else if (job.isComplete() && job.getJsonReport() != null) {
                Intent intent = new Intent(v.getContext(), ReportActivity.class);
                intent.putExtra("APP_NAME", job.getAppName());
                intent.putExtra("JSON_REPORT", job.getJsonReport());
                v.getContext().startActivity(intent);
            } else {
                Toast.makeText(
                        v.getContext(),
                        v.getContext().getString(R.string.toast_analysis_running),
                        Toast.LENGTH_SHORT
                ).show();
            }
        });

        // Long press
        holder.itemView.setOnLongClickListener(v -> {
            new MaterialAlertDialogBuilder(v.getContext())
                    .setTitle(v.getContext().getString(R.string.delete_record_title))
                    .setMessage(v.getContext().getString(R.string.delete_record_message, job.getAppName()))
                    .setPositiveButton(v.getContext().getString(R.string.action_delete), (dialog, which) -> {
                        ScanManager.getInstance().deleteScanHistory(
                                v.getContext(),
                                job.getAppName(),
                                job.isComplete()
                        );
                    })
                    .setNegativeButton(v.getContext().getString(R.string.action_cancel), null)
                    .show();

            return true;
        });

        // Cancel
        holder.btnCancelScan.setOnClickListener(v -> {
            new MaterialAlertDialogBuilder(v.getContext())
                    .setTitle(v.getContext().getString(R.string.cancel_analysis_title))
                    .setMessage(v.getContext().getString(R.string.cancel_analysis_message, job.getAppName()))
                    .setPositiveButton(v.getContext().getString(R.string.action_abort_scan), (dialog, which) -> {
                        ScanManager.getInstance().abortActiveScan(job.getAppName());
                    })
                    .setNegativeButton(v.getContext().getString(R.string.action_keep_scanning), (dialog, which) -> {
                        dialog.dismiss();
                    })
                    .show();
        });
    }

    @Override
    public int getItemCount() {
        return scanJobs.size();
    }

    static class ProgressViewHolder extends RecyclerView.ViewHolder {
        TextView textAppName;
        TextView textStatusLog;
        ProgressBar progressSpinner;
        ImageView iconComplete;
        ImageView btnCancelScan;

        public ProgressViewHolder(@NonNull View itemView) {
            super(itemView);
            textAppName = itemView.findViewById(R.id.textAppName);
            textStatusLog = itemView.findViewById(R.id.textStatusLog);
            progressSpinner = itemView.findViewById(R.id.progressSpinner);
            iconComplete = itemView.findViewById(R.id.iconComplete);
            btnCancelScan = itemView.findViewById(R.id.btnCancelScan);
        }
    }
}