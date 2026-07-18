package com.security.droidguard.ui.activity;

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

        MaterialToolbar toolbar = findViewById(R.id.reportToolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        MaterialCardView cardVerdict = findViewById(R.id.cardVerdict);
        TextView textAppName = findViewById(R.id.textReportAppName);
        TextView textVerdict = findViewById(R.id.textVerdict);
        TextView textScore = findViewById(R.id.textScore);
        TextView textReasoning = findViewById(R.id.textReasoning);
        TextView textDetails = findViewById(R.id.textDetails);

        String appName = getIntent().getStringExtra("APP_NAME");
        String jsonString = getIntent().getStringExtra("JSON_REPORT");

        if (appName != null) textAppName.setText(appName);

        try {
            JSONObject report = new JSONObject(jsonString);

            String rawVerdict = report.optString("verdict", "unknown").toLowerCase();
            double score = report.optDouble("threat_score", 0.0);

            String reason = report.optString("reason", getString(R.string.reasoning_default));

            String localizedVerdict;
            switch (rawVerdict) {
                case "clean":
                    localizedVerdict = getString(R.string.verdict_clean);
                    cardVerdict.setCardBackgroundColor(ContextCompat.getColor(this, R.color.report_safe_bg));
                    textVerdict.setTextColor(ContextCompat.getColor(this, R.color.report_safe_text));

                    break;
                case "suspicious":
                    localizedVerdict = getString(R.string.verdict_suspicious);
                    cardVerdict.setCardBackgroundColor(ContextCompat.getColor(this, R.color.report_suspicious_bg));
                    textVerdict.setTextColor(ContextCompat.getColor(this, R.color.report_suspicious_text));

                    break;
                case "malicious":
                    localizedVerdict = getString(R.string.verdict_malicious);
                    cardVerdict.setCardBackgroundColor(ContextCompat.getColor(this, R.color.report_malicious_bg));
                    textVerdict.setTextColor(ContextCompat.getColor(this, R.color.report_malicious_text));

                    break;
                default:
                    localizedVerdict = getString(R.string.verdict_unknown);
                    break;
            }

            textVerdict.setText(localizedVerdict.toUpperCase());

            textScore.setText(getString(R.string.threat_score_format, String.valueOf(score)));

            textReasoning.setText(reason);

            JSONObject yara = report.optJSONObject("yara_summary");
            JSONObject androguard = report.optJSONObject("androguard_summary");

            StringBuilder details = new StringBuilder();
            if (yara != null) {
                int threatsFound = yara.optInt("threats_found", 0);
                details.append(getString(R.string.yara_threats_found, threatsFound)).append("\n");
            }
            if (androguard != null) {
                int highSeverity = androguard.optInt("high_severity_count", 0);
                details.append(getString(R.string.high_severity_heuristics, highSeverity));
            }
            textDetails.setText(details.toString());

        } catch (Exception e) {
            e.printStackTrace();
            textReasoning.setText(getString(R.string.failed_parse, jsonString));
        }
    }
}