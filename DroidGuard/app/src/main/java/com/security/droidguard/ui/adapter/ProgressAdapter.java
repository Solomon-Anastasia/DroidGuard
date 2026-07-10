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

    // Called by ProgressActivity whenever LiveData emits a new list
    public void updateData(List<ScanJob> newJobs) {
        this.scanJobs = newJobs;
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
        holder.textStatusLog.setText(job.getStatusLog());

        // Toggle UI based on whether the Gateway finished the job
        if (job.isComplete()) {
            holder.progressSpinner.setVisibility(View.GONE);
            holder.iconComplete.setVisibility(View.VISIBLE);
            holder.btnCancelScan.setVisibility(android.view.View.GONE);
        } else {
            holder.progressSpinner.setVisibility(View.VISIBLE);
            holder.iconComplete.setVisibility(View.GONE);
            holder.btnCancelScan.setVisibility(android.view.View.VISIBLE);
        }

        holder.itemView.setOnClickListener(v -> {
            if (job.isComplete() && job.getJsonReport() != null) {
                // If finished, launch the Report Activity
                Intent intent = new Intent(v.getContext(), ReportActivity.class);
                intent.putExtra("APP_NAME", job.getAppName());
                intent.putExtra("JSON_REPORT", job.getJsonReport());
                v.getContext().startActivity(intent);
            } else {
                // If still scanning, give user feedback
                Toast.makeText(v.getContext(), "Analysis is still running...", Toast.LENGTH_SHORT).show();
            }
        });

        holder.itemView.setOnLongClickListener(v -> {
            new MaterialAlertDialogBuilder(v.getContext())
                    .setTitle("Delete record?")
                    .setMessage("Remove the scan history for " + job.getAppName() + "?")
                    .setPositiveButton("Delete", (dialog, which) -> {

                        // Call the delete method we just made!
                        ScanManager.getInstance().deleteScanHistory(v.getContext(), job.getAppName());

                    })
                    .setNegativeButton("Cancel", null)
                    .show();

            return true; // Tells Android we handled the long-click
        });

        holder.btnCancelScan.setOnClickListener(v -> {
            new MaterialAlertDialogBuilder(v.getContext())
                    .setTitle("Cancel Analysis?")
                    .setMessage("Are you sure you want to abort the malware scan for " + job.getAppName() + "?")
                    .setPositiveButton("Abort scan", (dialog, which) -> {
                        // This is your original cancellation code!
                        ScanManager.getInstance().abortActiveScan(job.getAppName());
                    })
                    .setNegativeButton("Keep scanning", (dialog, which) -> {
                        // Just dismiss the popup and do nothing
                        dialog.dismiss();
                    })
                    .show();
        });

        holder.itemView.setOnClickListener(v -> {
            if (job.isComplete() && job.getJsonReport() != null) {
                Intent intent = new Intent(v.getContext(), ReportActivity.class);

                // Pass the App Name and the Raw JSON string to the new Activity
                intent.putExtra("APP_NAME", job.getAppName());
                intent.putExtra("JSON_REPORT", job.getJsonReport());

                v.getContext().startActivity(intent);
            }
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