package com.security.droidguard.ui.activity;

import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.card.MaterialCardView;
import com.security.droidguard.R;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

        LinearLayout findingsContainer = findViewById(R.id.layoutFindingsContainer);
        String jsonString = getIntent().getStringExtra("JSON_REPORT");
        String appName = getIntent().getStringExtra("APP_NAME");

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

            String scanDuration = report.optString("scan_duration_formatted", "00:00");
            String durationText = getString(R.string.scan_duration_label, scanDuration);

            reason = reason + "\n\n" + durationText;
            textReasoning.setText(reason);

            JSONObject androguardReport = report.optJSONObject("androguard_report");
            if (androguardReport != null && androguardReport.has("findings")) {
                JSONArray findings = androguardReport.optJSONArray("findings");

                Map<String, List<JSONObject>> groupedFindings = new LinkedHashMap<>();
                for (int i = 0; i < findings.length(); i++) {
                    JSONObject finding = findings.optJSONObject(i);
                    if (finding != null) {
                        String type = finding.optString("type", "unknown");
                        if (!groupedFindings.containsKey(type)) {
                            groupedFindings.put(type, new ArrayList<>());
                        }
                        groupedFindings.get(type).add(finding);
                    }
                }

                for (Map.Entry<String, List<JSONObject>> entry : groupedFindings.entrySet()) {
                    String type = entry.getKey();
                    List<JSONObject> typeFindings = entry.getValue();

                    String maxSeverity = "low";
                    StringBuilder detailBuilder = new StringBuilder();

                    for (JSONObject finding : typeFindings) {
                        String severity = finding.optString("severity", "low");
                        if ("high".equals(severity)) maxSeverity = "high";
                        else if ("medium".equals(severity) && !"high".equals(maxSeverity))
                            maxSeverity = "medium";

                        String name = finding.optString("name", "");
                        String detail = finding.optString("detail", "");

                        if (type.equals("exported_component_without_permission")) {
                            String compType = finding.optString("component_type", "component");
                            JSONArray sensitiveActions = finding.optJSONArray("sensitive_actions");

                            detailBuilder.append("- ").append(name).append(" (").append(compType).append(")");
                            if (sensitiveActions != null && sensitiveActions.length() > 0) {
                                detailBuilder.append("\n   Actions: ");
                                for (int k = 0; k < sensitiveActions.length(); k++) {
                                    if (k > 0) detailBuilder.append(", ");
                                    detailBuilder.append(sensitiveActions.optString(k));
                                }
                            }
                            detailBuilder.append("\n\n");
                        } else {
                            detailBuilder.append("- ").append(name);
                            if (!detail.isEmpty()) {
                                detailBuilder.append("\n   ").append(detail);
                            }
                            detailBuilder.append("\n\n");
                        }
                    }

                    String localizedCategory = getLocalizedStringForType(type, type);
                    if (typeFindings.size() > 1) {
                        localizedCategory += " (" + typeFindings.size() + ")";
                    }

                    int textColor = 0;
                    if ("high".equals(maxSeverity)) {
                        textColor = ContextCompat.getColor(this, R.color.report_malicious_text);
                    } else if ("medium".equals(maxSeverity)) {
                        textColor = ContextCompat.getColor(this, R.color.report_suspicious_text);
                    }

                    addExpandableFinding(findingsContainer, localizedCategory, detailBuilder.toString().trim(), textColor);
                }
            }

            JSONObject breakdown = report.optJSONObject("signal_breakdown");
            if (breakdown != null) {
                JSONObject behaviors = breakdown.optJSONObject("behaviors");
                boolean evasionPresent = breakdown.optBoolean("evasion_present", false);

                if (behaviors != null) {
                    StringBuilder behaviorDetails = new StringBuilder();
                    int count = 0;

                    Iterator<String> keys = behaviors.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        JSONObject behaviorObj = behaviors.optJSONObject(key);
                        if (behaviorObj != null) {
                            double behaviorScore = behaviorObj.optDouble("score", 0.0);
                            boolean corroborated = behaviorObj.optBoolean("corroborated", false);

                            if (behaviorScore >= 0.3) {
                                count++;
                                String title = getLocalizedStringForType("behavior_" + key, key);
                                behaviorDetails.append("- ").append(title)
                                        .append("\n   ").append(getString(R.string.behavior_score_detail, String.valueOf(behaviorScore)));
                                if (corroborated) {
                                    behaviorDetails.append(" (").append(getString(R.string.corroborated_tag)).append(")");
                                }
                                behaviorDetails.append("\n\n");
                            }
                        }
                    }

                    if (count > 0) {
                        String categoryTitle = getString(R.string.category_behavior_signals) + " (" + count + ")";
                        addExpandableFinding(findingsContainer, categoryTitle, behaviorDetails.toString().trim(), 0);
                    }
                }

                if (evasionPresent) {
                    addExpandableFinding(
                            findingsContainer,
                            getString(R.string.evasion_detected_title),
                            getString(R.string.evasion_detected_detail),
                            ContextCompat.getColor(this, R.color.report_suspicious_text)
                    );
                }
            }

            JSONObject yaraReport = report.optJSONObject("yara_report");
            if (yaraReport != null && yaraReport.has("matches")) {
                JSONArray matches = yaraReport.optJSONArray("matches");
                if (matches.length() > 0) {
                    StringBuilder yaraDetails = new StringBuilder();
                    String maxConfidence = "low";

                    for (int i = 0; i < matches.length(); i++) {
                        JSONObject match = matches.optJSONObject(i);
                        if (match != null) {
                            String rule = match.optString("rule", "");
                            String file = match.optString("file", "");
                            String confidence = match.optString("confidence", "low");

                            if ("high".equals(confidence))
                                maxConfidence = "high";
                            else if ("medium".equals(confidence) && !"high".equals(maxConfidence))
                                maxConfidence = "medium";

                            yaraDetails.append("- Rule: ").append(rule)
                                    .append("\n   File: ").append(file)
                                    .append(" | Confidence: ").append(confidence)
                                    .append("\n\n");
                        }
                    }

                    String categoryTitle = getString(R.string.category_yara_matches) + " (" + matches.length() + ")";
                    int textColor = 0;
                    if ("high".equals(maxConfidence) || "medium".equals(maxConfidence)) {
                        textColor = ContextCompat.getColor(this, R.color.report_malicious_text);
                    }

                    addExpandableFinding(findingsContainer, categoryTitle, yaraDetails.toString().trim(), textColor);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            textReasoning.setText(getString(R.string.failed_parse, jsonString));
        }
    }

    private void addExpandableFinding(LinearLayout container, String title, String detail, int titleColor) {
        View view = getLayoutInflater().inflate(R.layout.item_finding, container, false);
        TextView titleView = view.findViewById(R.id.textFindingTitle);
        TextView detailView = view.findViewById(R.id.textFindingDetail);
        ImageView iconExpand = view.findViewById(R.id.iconExpand);

        titleView.setText(title);
        if (titleColor != 0) {
            titleView.setTextColor(titleColor);
        }

        if (detail != null && !detail.isEmpty()) {
            detailView.setText(detail);
            detailView.setVisibility(View.GONE);

            view.setOnClickListener(v -> {
                boolean isExpanded = detailView.getVisibility() == View.VISIBLE;
                detailView.setVisibility(isExpanded ? View.GONE : View.VISIBLE);
                iconExpand.animate().rotation(isExpanded ? 0 : 180).setDuration(200).start();
            });
        } else {
            detailView.setVisibility(View.GONE);
            iconExpand.setVisibility(View.GONE);
            view.setClickable(false);
        }

        container.addView(view);
    }

    private String getLocalizedStringForType(String type, String fallbackName) {
        String resourceName = "threat_" + type;
        int resId = getResources().getIdentifier(resourceName, "string", getPackageName());

        if (resId != 0) {
            return getString(resId);
        }
        return fallbackName;
    }
}