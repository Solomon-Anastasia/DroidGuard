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
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.textfield.TextInputEditText;
import com.security.droidguard.R;
import com.security.droidguard.models.ScanJob;
import com.security.droidguard.network.ScanManager;
import com.security.droidguard.ui.adapter.ProgressAdapter;

import java.util.ArrayList;
import java.util.List;

public class ProgressActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_progress);

        MaterialToolbar toolbar = findViewById(R.id.progressToolbar);
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

        ChipGroup chipGroup = findViewById(R.id.chipGroupFilter);

        String incomingFilter = getIntent().getStringExtra("FILTER_TYPE");
        if ("clean".equals(incomingFilter)) {
            chipGroup.check(R.id.chipFilterSafe);
            activeAdapter.setFilter(null, "clean");
            completedAdapter.setFilter(null, "clean");
        } else if ("suspicious".equals(incomingFilter)) {
            chipGroup.check(R.id.chipFilterSuspicious);
            activeAdapter.setFilter(null, "malicious");
            completedAdapter.setFilter(null, "malicious");
        }

        chipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;

            int checkedId = checkedIds.get(0);
            String verdictFilter = "all";

            if (checkedId == R.id.chipFilterSafe) verdictFilter = "clean";
            else if (checkedId == R.id.chipFilterSuspicious) verdictFilter = "malicious";

            activeAdapter.setFilter(null, verdictFilter);
            completedAdapter.setFilter(null, verdictFilter);

            titleActive.setVisibility(verdictFilter.equals("all") &&
                    activeAdapter.getItemCount() > 0 ? View.VISIBLE : View.GONE);
        });

        TextInputEditText searchInput = findViewById(R.id.searchProgressInput);
        searchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                activeAdapter.setFilter(s.toString(), null);
                completedAdapter.setFilter(s.toString(), null);
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