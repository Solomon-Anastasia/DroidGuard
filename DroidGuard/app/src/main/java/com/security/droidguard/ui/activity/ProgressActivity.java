package com.security.droidguard.ui.activity;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.textfield.TextInputEditText;
import com.security.droidguard.R;
import com.security.droidguard.network.ScanManager;
import com.security.droidguard.ui.adapter.ProgressAdapter;

public class ProgressActivity extends AppCompatActivity {
    private MaterialToolbar toolbar;
    private RecyclerView recyclerActiveScans;
    private ProgressAdapter adapter;

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

        recyclerActiveScans = findViewById(R.id.recyclerActiveScans);
        recyclerActiveScans.setLayoutManager(new LinearLayoutManager(this));

        adapter = new ProgressAdapter();
        recyclerActiveScans.setAdapter(adapter);

        TextInputEditText searchInput = findViewById(R.id.searchProgressInput);
        searchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // Not needed
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (adapter != null) {
                    adapter.filter(s.toString());
                }
            }

            @Override
            public void afterTextChanged(Editable s) {
                // Not needed
            }
        });

        ScanManager.getInstance().getActiveScans().observe(this, scanJobs -> {
            adapter.updateData(scanJobs);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        ScanManager.getInstance().syncActiveScans();
    }
}