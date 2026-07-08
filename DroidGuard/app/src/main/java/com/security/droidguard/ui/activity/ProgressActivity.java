package com.security.droidguard.ui.activity;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.security.droidguard.R;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ScanManager;
import com.security.droidguard.ui.adapter.ProgressAdapter;

import java.util.List;

public class ProgressActivity extends AppCompatActivity {

    private MaterialToolbar toolbar;
    private RecyclerView recyclerActiveScans;
    private ProgressAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_progress);

        // 1. Setup Toolbar
        toolbar = findViewById(R.id.progressToolbar);
        setSupportActionBar(toolbar);

        // This overrides the back arrow to jump straight to the Dashboard
        toolbar.setNavigationOnClickListener(v -> {
            Intent intent = new Intent(ProgressActivity.this, DashboardActivity.class);
            // This flag wipes MainActivity and ProgressActivity from the back-stack
            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });

        // 2. Setup RecyclerView & Adapter
        recyclerActiveScans = findViewById(R.id.recyclerActiveScans);
        recyclerActiveScans.setLayoutManager(new LinearLayoutManager(this));

        adapter = new ProgressAdapter();
        recyclerActiveScans.setAdapter(adapter);

        // 3. Observe the live data stream from the background ScanManager
        ScanManager.getInstance().getActiveScans().observe(this, new Observer<List<ScanJob>>() {
            @Override
            public void onChanged(List<ScanJob> scanJobs) {
                // Instantly pushes the new data (progress text, completion status) to the screen
                adapter.updateData(scanJobs);
            }
        });
    }
}