package com.security.droidguard.ui.activity;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.textfield.TextInputEditText;
import com.security.droidguard.R;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ScanManager;
import com.security.droidguard.ui.adapter.ProgressAdapter;

import java.util.ArrayList;
import java.util.List;

public class ProgressActivity extends AppCompatActivity {
    private MaterialToolbar toolbar;
    private RecyclerView recyclerActiveScans;
    private ProgressAdapter adapter;

    //    @Override
//    protected void onCreate(Bundle savedInstanceState) {
//        super.onCreate(savedInstanceState);
//        setContentView(R.layout.activity_progress);
//
//        toolbar = findViewById(R.id.progressToolbar);
//        setSupportActionBar(toolbar);
//
//        toolbar.setNavigationOnClickListener(v -> {
//            Intent intent = new Intent(ProgressActivity.this, DashboardActivity.class);
//            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
//            startActivity(intent);
//            finish();
//        });
//
//        SwipeRefreshLayout swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout);
//        swipeRefreshLayout.setOnRefreshListener(() -> {
//            ScanManager.getInstance().syncActiveScans();
//            swipeRefreshLayout.setRefreshing(false);
//        });
//
//        recyclerActiveScans = findViewById(R.id.recyclerActiveScans);
//        recyclerActiveScans.setLayoutManager(new LinearLayoutManager(this));
//
//        adapter = new ProgressAdapter();
//        recyclerActiveScans.setAdapter(adapter);
//
//        TextInputEditText searchInput = findViewById(R.id.searchProgressInput);
//        searchInput.addTextChangedListener(new TextWatcher() {
//            @Override
//            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
//                // Not needed
//            }
//
//            @Override
//            public void onTextChanged(CharSequence s, int start, int before, int count) {
//                if (adapter != null) {
//                    adapter.filter(s.toString());
//                }
//            }
//
//            @Override
//            public void afterTextChanged(Editable s) {
//                // Not needed
//            }
//        });
//
//        ScanManager.getInstance().getActiveScans().observe(this, scanJobs -> {
//            adapter.updateData(scanJobs);
//        });
//    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_progress);

        toolbar = findViewById(R.id.progressToolbar);
        setSupportActionBar(toolbar);

        toolbar.setNavigationOnClickListener(v -> {
            Intent intent = new Intent(ProgressActivity.this, DashboardActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });

        SwipeRefreshLayout swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout);
        swipeRefreshLayout.setOnRefreshListener(() -> {
            ScanManager.getInstance().syncActiveScans();
            swipeRefreshLayout.setRefreshing(false);
        });

        RecyclerView recyclerActiveScans = findViewById(R.id.recyclerActiveScans);
        RecyclerView recyclerCompletedScans = findViewById(R.id.recyclerCompletedScans);

        TextView titleActive = findViewById(R.id.titleActive);
        TextView titleCompleted = findViewById(R.id.titleCompleted);

        recyclerActiveScans.setLayoutManager(new LinearLayoutManager(this));
        recyclerCompletedScans.setLayoutManager(new LinearLayoutManager(this));

        ProgressAdapter activeAdapter = new ProgressAdapter();
        ProgressAdapter completedAdapter = new ProgressAdapter();

        recyclerActiveScans.setAdapter(activeAdapter);
        recyclerCompletedScans.setAdapter(completedAdapter);

        TextInputEditText searchInput = findViewById(R.id.searchProgressInput);
        searchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // Not needed
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                activeAdapter.filter(s.toString());
                completedAdapter.filter(s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {
                // Not needed
            }
        });

        ScanManager.getInstance().getActiveScans().observe(this, scanJobs -> {
            List<ScanJob> activeJobs = new ArrayList<>();
            List<ScanJob> completedJobs = new ArrayList<>();

            for (ScanJob job : scanJobs) {
                if (job.isComplete()) {
                    completedJobs.add(job);
                } else {
                    activeJobs.add(job);
                }
            }

            activeAdapter.updateData(activeJobs);
            completedAdapter.updateData(completedJobs);

            titleActive.setVisibility(activeJobs.isEmpty() ? View.GONE : View.VISIBLE);
            titleCompleted.setVisibility(completedJobs.isEmpty() ? View.GONE : View.VISIBLE);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        ScanManager.getInstance().syncActiveScans();
    }
}