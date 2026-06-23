package com.example.yaradroid;

import android.os.Bundle;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.yaradroid.extractor.ApkExtractor;
import com.example.yaradroid.models.InstalledApp;
import com.example.yaradroid.network.AnalysisProxy;
import com.example.yaradroid.ui.AppListAdapter;

import java.util.List;

public class MainActivity extends AppCompatActivity {
    private RecyclerView recyclerView;
    private AppListAdapter adapter;
    private AnalysisProxy analysisProxy;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        analysisProxy = new AnalysisProxy();

        recyclerView = findViewById(R.id.recyclerView);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        List<InstalledApp> installedApps = ApkExtractor.getUserApps(this);

        adapter = new AppListAdapter(installedApps, app -> {
            Toast.makeText(MainActivity.this, "Scanning: " + app.getAppName(), Toast.LENGTH_SHORT).show();

            analysisProxy.startAnalysis(app.getApkPath(), new AnalysisProxy.AnalysisCallback() {
                @Override
                public void onSuccess(String jsonReport) {
                    // For now, just show a Toast
                    Toast.makeText(MainActivity.this, "Report Ready!", Toast.LENGTH_LONG).show();
                }

                @Override
                public void onError(String error) {
                    Toast.makeText(MainActivity.this, "Error: " + error, Toast.LENGTH_LONG).show();
                }
            });
        });

        recyclerView.setAdapter(adapter);
    }
}