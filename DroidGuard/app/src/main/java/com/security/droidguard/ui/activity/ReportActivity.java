package com.security.droidguard.ui.activity;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.security.droidguard.R;

import org.json.JSONObject;

public class ReportActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_report);

        MaterialToolbar toolbar = findViewById(R.id.reportToolbar);
        TextView textReportContent = findViewById(R.id.textReportContent);

        setSupportActionBar(toolbar);
        toolbar.setNavigationOnClickListener(v -> finish()); // Closes screen on back arrow

        // Unpack the data sent from the Adapter
        if (getIntent() != null) {
            String appName = getIntent().getStringExtra("APP_NAME");
            String rawJson = getIntent().getStringExtra("JSON_REPORT");

            // Update toolbar title dynamically
            if (appName != null) {
                toolbar.setTitle(appName + " report");
            }

            // Display the data (with pretty-printing if it is valid JSON)
            if (rawJson != null) {
                try {
                    // Try to format the JSON so it looks nice on screen
                    JSONObject jsonObject = new JSONObject(rawJson);
                    textReportContent.setText(jsonObject.toString(4));
                } catch (Exception e) {
                    // Fallback to raw string if parsing fails
                    textReportContent.setText(rawJson);
                }
            } else {
                textReportContent.setText("No report data available.");
            }
        }
    }
}