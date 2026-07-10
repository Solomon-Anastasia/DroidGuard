package com.security.droidguard.ui.activity;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.card.MaterialCardView;
import com.security.droidguard.R;
import org.json.JSONObject;

public class ReportActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_report);

        // Setup Toolbar back button
        MaterialToolbar toolbar = findViewById(R.id.reportToolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        // Bind UI Elements
        MaterialCardView cardVerdict = findViewById(R.id.cardVerdict);
        TextView textAppName = findViewById(R.id.textReportAppName);
        TextView textVerdict = findViewById(R.id.textVerdict);
        TextView textScore = findViewById(R.id.textScore);
        TextView textReasoning = findViewById(R.id.textReasoning);
        TextView textDetails = findViewById(R.id.textDetails);

        // 1. Get the data passed from the previous screen
        String appName = getIntent().getStringExtra("APP_NAME");
        String jsonString = getIntent().getStringExtra("JSON_REPORT");

        if (appName != null) textAppName.setText(appName);

        // 2. Parse the JSON safely
        try {
            JSONObject report = new JSONObject(jsonString);

            // Extract core fields defined in your Python verdict.py
            String verdict = report.optString("verdict", "UNKNOWN");
            double score = report.optDouble("threat_score", 0.0);
            String reason = report.optString("reason", "No detailed reasoning provided.");

            // Update text fields
            textVerdict.setText(verdict.toUpperCase());
            textScore.setText("Threat score: " + score + " / 1.0");
            textReasoning.setText(reason);

            // 3. Dynamic Color Styling based on verdict
            if ("clean".equalsIgnoreCase(verdict)) {
                cardVerdict.setCardBackgroundColor(ContextCompat.getColor(this, R.color.report_safe_bg));
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.report_safe_text));

            } else if ("suspicious".equalsIgnoreCase(verdict)) {
                cardVerdict.setCardBackgroundColor(ContextCompat.getColor(this, R.color.report_suspicious_bg));
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.report_suspicious_text));

            } else if ("malicious".equalsIgnoreCase(verdict)) {
                cardVerdict.setCardBackgroundColor(ContextCompat.getColor(this, R.color.report_malicious_bg));
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.report_malicious_text));
            }

            // 4. (Optional) Extract summary metrics
            JSONObject yara = report.optJSONObject("yara_summary");
            JSONObject androguard = report.optJSONObject("androguard_summary");

            StringBuilder details = new StringBuilder();
            if (yara != null) {
                details.append("YARA Threats Found: ").append(yara.optInt("threats_found", 0)).append("\n");
            }
            if (androguard != null) {
                details.append("High Severity Heuristics: ").append(androguard.optInt("high_severity_count", 0));
            }
            textDetails.setText(details.toString());

        } catch (Exception e) {
            e.printStackTrace();
            textReasoning.setText("Failed to parse report data.\n\nRaw Data:\n" + jsonString);
        }
    }
}