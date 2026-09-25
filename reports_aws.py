#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Athena AWS Cloud Health Report

Purpose:
  Dedicated Amazon Web Services security and operations reporting module for Athena.
  This script follows the same email layout, configuration pattern, LLM JSON handling,
  comparison logic, and Athena AI presentation style used by reports_gcp.py.

Usage:
  python reports_aws.py daily
  python reports_aws.py weekly
  python reports_aws.py monthly
  python reports_aws.py custom <recipients_optional_ignored> <start_time> <end_time>

Expected source fields:
  data.integration: aws
  data.aws.* from AWS services collected into the SIEM
"""

import json
import sys
import time
import os
import smtplib
import html
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from email.message import EmailMessage
from email.utils import formataddr
from dotenv import load_dotenv

load_dotenv()

# === CONFIGURATION FROM ENVIRONMENT ===
ATHENA_NAME = os.getenv("ATHENA_NAME", "Athena SOC")
TENANT_NAME = os.getenv("TENANT_NAME", "test.athenasecuritygrp.com")
ATHENA_WEBSITE = os.getenv("ATHENA_WEBSITE", "https://athenasoftwaregroup.ai/")
ATHENA_DOCS = os.getenv("ATHENA_DOCS", "https://athenasoftwaregroup.ai/")
ATHENA_SUPPORT = os.getenv("ATHENA_SUPPORT", "alerts@athena.athenasecuritygrp.com")
DASHBOARD_BASE_URL = os.getenv("DASHBOARD_BASE_URL", "")

# === SMTP CONFIGURATION ===
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "alerts@athenasoftwaregrp.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "alerts@athena.athenasecuritygrp.com")
SMTP_RECIPIENT = [r.strip() for r in os.getenv("SMTP_RECIPIENT", "secops@athena.athenasecuritygrp.com").split(",") if r.strip()]

# === REPORT MODULE TOGGLE ===
REPORT_AWS_ENABLED = os.getenv("REPORT_AWS_ENABLED", "true").lower() == "true"

# === LLM CONFIGURATION ===
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://router.huggingface.co/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V3.1-Terminus")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"
HF_ORG_NAME = os.getenv("HF_ORG_NAME", "").strip()
LLM_CHAT_URL = f"{LLM_BASE_URL}/chat/completions"

# === ELASTICSEARCH / OPENSEARCH CONFIGURATION ===
ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USERNAME = os.getenv("ES_USERNAME", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_INDEX_PATTERN = os.getenv("ES_INDEX_PATTERN_AWS", os.getenv("ES_INDEX_PATTERN_SIEM", "wazuh-alerts-*"))
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"

# === LOGGING ===
pwd = os.path.dirname(os.path.realpath(__file__))
log_file = f"{pwd}/logs/reporting_aws.log"


def log(msg: str):
    now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
    line = f"{now}: {msg}\n"
    print(line, end="")
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "a") as f:
            f.write(line)
    except Exception:
        pass


def build_llm_headers() -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_API_KEY}",
    }
    if HF_ORG_NAME:
        headers["X-HF-Bill-To"] = HF_ORG_NAME
    return headers


def _parse_llm_json(ai_content, finish_reason=None):
    if finish_reason and finish_reason != "stop":
        log(f"LLM finish_reason={finish_reason!r}; output may be truncated")
    if not ai_content or not ai_content.strip():
        log("LLM returned empty content; using fallback Athena AI analysis")
        return None
    text = ai_content.strip()
    if text.startswith("```"):
        text = text[3:]
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.lstrip()
        if text.endswith("```"):
            text = text[:-3].rstrip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last > first:
            try:
                return json.loads(text[first:last + 1])
            except json.JSONDecodeError:
                pass
    snippet = ai_content[:300].replace("\n", " ")
    log(f"Failed to parse LLM response as JSON. Raw content first 300 chars: {snippet!r}")
    return None


def es_post_search(query: dict) -> dict:
    try:
        import requests
        from requests.auth import HTTPBasicAuth
        import urllib3
        if not ES_VERIFY_SSL:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.post(
            f"{ES_HOST}/{ES_INDEX_PATTERN}/_search",
            json=query,
            auth=HTTPBasicAuth(ES_USERNAME, ES_PASSWORD),
            verify=ES_VERIFY_SSL,
            timeout=45,
        )
        if response.status_code == 200:
            return response.json().get("aggregations", {})
        log(f"OpenSearch query failed: {response.status_code} - {response.text}")
        return {}
    except Exception as e:
        log(f"Error querying OpenSearch: {e}")
        return {}


# === DASHBOARD URL BUILDER - SAME STYLE AS GCP SCRIPT ===
def build_dashboard_url(time_from, time_to, filters=None):
    # Dashboard links are optional. If no absolute dashboard base URL is configured,
    # return an empty string so email clients do not expose broken relative URLs.
    dashboard_base = (DASHBOARD_BASE_URL or "").strip().rstrip("/")
    if not dashboard_base.lower().startswith(("http://", "https://")):
        return ""
    base = f"{dashboard_base}/app/discover#"
    filter_rison = "!()"
    if filters:
        filter_items = []
        for f in filters:
            if f["type"] == "phrase":
                field = str(f["field"])
                value = str(f["value"])
                field_escaped = field.replace("\\", "\\\\").replace("'", "\\'")
                value_escaped = value.replace("\\", "\\\\").replace("'", "\\'")
                index_pattern_escaped = ES_INDEX_PATTERN.replace("\\", "\\\\").replace("'", "\\'")
                filter_items.append(
                    f"(meta:(alias:!n,disabled:!f,index:'{index_pattern_escaped}',key:'{field_escaped}',negate:!f,params:(query:'{value_escaped}'),type:phrase,value:'{value_escaped}'),query:(match_phrase:({field_escaped}:'{value_escaped}')))"
                )
            elif f["type"] == "range":
                field = str(f["field"])
                field_escaped = field.replace("\\", "\\\\").replace("'", "\\'")
                index_pattern_escaped = ES_INDEX_PATTERN.replace("\\", "\\\\").replace("'", "\\'")
                params = f.get("params", {})
                parts = []
                for k in ("gte", "lte", "lt"):
                    if params.get(k) is not None:
                        parts.append(f"{k}:{params.get(k)}")
                params_str = ",".join(parts)
                filter_items.append(
                    f"(meta:(alias:!n,disabled:!f,index:'{index_pattern_escaped}',key:'{field_escaped}',negate:!f,params:({params_str}),type:range),range:({field_escaped}:({params_str})))"
                )
        if filter_items:
            filter_rison = f"!({','.join(filter_items)})"
    index_pattern_escaped = ES_INDEX_PATTERN.replace("\\", "\\\\").replace("'", "\\'")
    _a = f"(columns:!(_source),filters:{filter_rison},index:'{index_pattern_escaped}',sort:!())"
    time_from_escaped = time_from.replace("'", "\\'")
    time_to_escaped = time_to.replace("'", "\\'")
    _g = f"(time:(from:'{time_from_escaped}',to:'{time_to_escaped}'))"
    _q = "(query:(language:kuery,query:''))"
    safe_chars = "()!,':"
    return f"{base}?_a={quote(_a, safe=safe_chars)}&_g={quote(_g, safe=safe_chars)}&_q={quote(_q, safe=safe_chars)}"


def calculate_previous_period(time_from, time_to, report_type):
    current_from = datetime.fromisoformat(time_from.replace("Z", "+00:00"))
    current_to = datetime.fromisoformat(time_to.replace("Z", "+00:00"))
    duration = current_to - current_from
    prev_to = current_from
    prev_from = prev_to - duration
    return prev_from.isoformat().replace("+00:00", "Z"), prev_to.isoformat().replace("+00:00", "Z")


def calculate_percentage_change(current, previous):
    if previous == 0:
        if current == 0:
            return 0, "no change"
        return 100, "increase"
    change = ((current - previous) / previous) * 100
    if change > 0:
        return change, "increase"
    if change < 0:
        return abs(change), "decrease"
    return 0, "no change"


# === AWS QUERY ===
def query_aws_data(time_from, time_to):
    """Query AWS events from OpenSearch."""
    log(f"Executing AWS aggregation query on {ES_INDEX_PATTERN}")
    aws_base_filter = [
        {"range": {"timestamp": {"gte": time_from, "lte": time_to, "format": "strict_date_optional_time"}}},
        {"term": {"data.integration": "aws"}},
    ]

    iam_methods = [
        "CreateUser", "DeleteUser", "CreateAccessKey", "DeleteAccessKey",
        "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
        "PutRolePolicy", "DeleteRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
        "CreatePolicy", "DeletePolicy", "CreateLoginProfile", "UpdateLoginProfile",
        "DeleteLoginProfile", "EnableMFADevice", "DeactivateMFADevice",
        "AddUserToGroup", "RemoveUserFromGroup", "UpdateAssumeRolePolicy",
    ]

    query = {
        "size": 0,
        "query": {"bool": {"filter": aws_base_filter}},
        "aggs": {
            "total_events": {"value_count": {"field": "rule.id"}},
            "sources": {"terms": {"field": "data.aws.source", "size": 20, "missing": "UNKNOWN"}},
            "accounts": {"terms": {"field": "data.aws.aws_account_id", "size": 20, "missing": "UNKNOWN"}},
            "accounts_alt": {"terms": {"field": "data.aws.accountId", "size": 20}},
            "regions": {"terms": {"field": "data.aws.region", "size": 20, "missing": "UNKNOWN"}},
            "regions_alt": {"terms": {"field": "data.aws.awsRegion", "size": 20}},
            "buckets": {"terms": {"field": "data.aws.log_info.s3bucket", "size": 20, "missing": "UNKNOWN"}},
            "top_event_names": {"terms": {"field": "data.aws.eventName", "size": 15, "missing": "UNKNOWN"}},
            "top_event_sources": {"terms": {"field": "data.aws.eventSource", "size": 15, "missing": "UNKNOWN"}},
            "top_source_ips": {"terms": {"field": "data.aws.sourceIPAddress", "size": 10, "missing": "UNKNOWN"}},
            "cloudtrail": {
                "filter": {"term": {"data.aws.source": "cloudtrail"}},
                "aggs": {
                    "methods": {"terms": {"field": "data.aws.eventName", "size": 10, "missing": "UNKNOWN"}},
                    "services": {"terms": {"field": "data.aws.eventSource", "size": 10, "missing": "UNKNOWN"}},
                },
            },
            "guardduty": {
                "filter": {"term": {"data.aws.source": "guardduty"}},
                "aggs": {
                    "types": {"terms": {"field": "data.aws.type", "size": 10, "missing": "UNKNOWN"}},
                    "severity": {"terms": {"field": "data.aws.severity", "size": 10, "missing": "UNKNOWN"}},
                },
            },
            "inspector2": {
                "filter": {"term": {"data.aws.source": "inspector2"}},
                "aggs": {
                    "types": {"terms": {"field": "data.aws.type", "size": 10, "missing": "UNKNOWN"}},
                    "severity": {"terms": {"field": "data.aws.severity", "size": 10, "missing": "UNKNOWN"}},
                },
            },
            "waf": {
                "filter": {"term": {"data.aws.source": "waf"}},
                "aggs": {
                    "actions": {"terms": {"field": "data.aws.action", "size": 10, "missing": "UNKNOWN"}},
                    "countries": {"terms": {"field": "data.aws.httpRequest.country", "size": 10, "missing": "UNKNOWN"}},
                    "client_ips": {"terms": {"field": "data.aws.httpRequest.clientIp", "size": 10, "missing": "UNKNOWN"}},
                },
            },
            "iam_changes": {
                "filter": {"terms": {"data.aws.eventName": iam_methods}},
                "aggs": {
                    "methods": {"terms": {"field": "data.aws.eventName", "size": 10}},
                    "source_ips": {"terms": {"field": "data.aws.sourceIPAddress", "size": 10, "missing": "UNKNOWN"}},
                },
            },
            "failed_api_calls": {
                "filter": {"bool": {"should": [
                    {"exists": {"field": "data.aws.errorCode"}},
                    {"exists": {"field": "data.aws.errorMessage"}},
                ], "minimum_should_match": 1}},
                "aggs": {
                    "methods": {"terms": {"field": "data.aws.eventName", "size": 10, "missing": "UNKNOWN"}},
                    "errors": {"terms": {"field": "data.aws.errorCode", "size": 10, "missing": "UNKNOWN"}},
                },
            },
            "root_activity": {
                "filter": {"term": {"data.aws.userIdentity.type": "Root"}},
                "aggs": {"methods": {"terms": {"field": "data.aws.eventName", "size": 10, "missing": "UNKNOWN"}}},
            },
            "destructive_activity": {
                "filter": {"bool": {"should": [
                    {"wildcard": {"data.aws.eventName": "Delete*"}},
                    {"wildcard": {"data.aws.eventName": "Terminate*"}},
                    {"wildcard": {"data.aws.eventName": "Disable*"}},
                    {"wildcard": {"data.aws.eventName": "Stop*"}},
                    {"wildcard": {"data.aws.eventName": "Revoke*"}},
                ], "minimum_should_match": 1}},
                "aggs": {"methods": {"terms": {"field": "data.aws.eventName", "size": 10, "missing": "UNKNOWN"}}},
            },
            "recent_samples": {
                "top_hits": {
                    "size": 5,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": [
                        "timestamp", "data.aws.source", "data.aws.accountId", "data.aws.aws_account_id",
                        "data.aws.region", "data.aws.awsRegion", "data.aws.eventName", "data.aws.eventSource",
                        "data.aws.sourceIPAddress", "data.aws.severity", "data.aws.type", "rule.description",
                    ],
                }
            },
        },
    }
    return es_post_search(query)


def _bucket_list(bucket_obj):
    return [(b.get("key", "UNKNOWN"), b.get("doc_count", 0)) for b in bucket_obj.get("buckets", [])]


def _merge_bucket_lists(primary, secondary):
    merged = {}
    for key, count in primary + secondary:
        if key == "UNKNOWN" and len(primary) == 1 and count == 0:
            continue
        merged[key] = max(merged.get(key, 0), count)
    return sorted(merged.items(), key=lambda x: x[1], reverse=True)


def analyze_aws(aggs):
    accounts = _merge_bucket_lists(_bucket_list(aggs.get("accounts", {})), _bucket_list(aggs.get("accounts_alt", {})))
    regions = _merge_bucket_lists(_bucket_list(aggs.get("regions", {})), _bucket_list(aggs.get("regions_alt", {})))

    stats = {
        "total_events": aggs.get("total_events", {}).get("value", 0),
        "sources": _bucket_list(aggs.get("sources", {})),
        "accounts": accounts,
        "regions": regions,
        "buckets": _bucket_list(aggs.get("buckets", {})),
        "top_event_names": _bucket_list(aggs.get("top_event_names", {})),
        "top_event_sources": _bucket_list(aggs.get("top_event_sources", {})),
        "top_source_ips": _bucket_list(aggs.get("top_source_ips", {})),
        "sections": {},
        "recent_samples": [h.get("_source", {}) for h in aggs.get("recent_samples", {}).get("hits", {}).get("hits", [])],
    }

    for name in ["cloudtrail", "guardduty", "inspector2", "waf", "iam_changes", "failed_api_calls", "root_activity", "destructive_activity"]:
        obj = aggs.get(name, {})
        stats["sections"][name] = {
            "count": obj.get("doc_count", 0),
            "methods": _bucket_list(obj.get("methods", {})),
            "services": _bucket_list(obj.get("services", {})),
            "types": _bucket_list(obj.get("types", {})),
            "severity": _bucket_list(obj.get("severity", {})),
            "actions": _bucket_list(obj.get("actions", {})),
            "countries": _bucket_list(obj.get("countries", {})),
            "client_ips": _bucket_list(obj.get("client_ips", {})),
            "source_ips": _bucket_list(obj.get("source_ips", {})),
            "errors": _bucket_list(obj.get("errors", {})),
        }

    risk_score = 0
    risk_score += stats["sections"]["root_activity"]["count"] * 5
    risk_score += stats["sections"]["iam_changes"]["count"] * 3
    risk_score += stats["sections"]["failed_api_calls"]["count"] * 2
    risk_score += stats["sections"]["destructive_activity"]["count"] * 2
    risk_score += stats["sections"]["guardduty"]["count"]
    risk_score += stats["sections"]["inspector2"]["count"]

    if risk_score >= 50:
        risk = "Critical"
    elif risk_score >= 20:
        risk = "High"
    elif risk_score >= 5:
        risk = "Medium"
    else:
        risk = "Low"

    stats["risk_score"] = risk_score
    stats["risk_rating"] = risk
    return stats


def get_aws_recommendations(stats):
    recs = []

    def add(area, priority, recommendation, benefit):
        recs.append({"area": area, "priority": priority, "recommendation": recommendation, "benefit": benefit})

    if stats["sections"]["iam_changes"]["count"] > 0:
        add("IAM", "High", "Review IAM changes during this period and confirm they map to approved requests.", "Reduces unauthorized privilege changes.")
    else:
        add("IAM", "Medium", "Regularly review IAM users, roles, policies, and inactive access keys.", "Maintains least-privilege access.")

    if stats["sections"]["root_activity"]["count"] > 0:
        add("Root Account", "High", "Review root-account activity and confirm it was required and authorized.", "Reduces risk from highly privileged access.")

    if stats["sections"]["failed_api_calls"]["count"] > 0:
        add("API Activity", "High", "Review failed AWS API calls by operation and source IP.", "Identifies access issues, misconfiguration, or suspicious attempts.")

    if stats["sections"]["guardduty"]["count"] > 0:
        add("GuardDuty", "High", "Review active GuardDuty findings and prioritize higher-severity findings.", "Improves response to AWS threat detections.")

    if stats["sections"]["inspector2"]["count"] > 0:
        add("Inspector", "High", "Review Inspector findings and prioritize remediation of high-severity vulnerabilities.", "Reduces exploitable cloud workload risk.")

    if stats["sections"]["destructive_activity"]["count"] > 0:
        add("Change Control", "High", "Validate delete, terminate, stop, disable, and revoke operations against approved changes.", "Reduces accidental or unauthorized service disruption.")

    add("Logging", "Medium", "Maintain CloudTrail coverage for required accounts and regions and protect the log storage location.", "Supports auditability and incident investigation.")
    add("WAF", "Medium", "Review blocked web requests, top client IPs, countries, and rule activity for recurring attack patterns.", "Improves web application protection tuning.")
    return recs[:10]


def fallback_ai_analysis(stats):
    concerns = []
    if stats["sections"]["root_activity"]["count"]:
        concerns.append(f"Root account activity observed: {stats['sections']['root_activity']['count']} event(s) require validation.")
    if stats["sections"]["iam_changes"]["count"]:
        concerns.append(f"IAM changes observed: {stats['sections']['iam_changes']['count']} event(s) require change validation.")
    if stats["sections"]["failed_api_calls"]["count"]:
        concerns.append(f"Failed AWS API calls observed: {stats['sections']['failed_api_calls']['count']} event(s) should be reviewed.")
    if stats["sections"]["destructive_activity"]["count"]:
        concerns.append(f"Destructive or service-impacting activity observed: {stats['sections']['destructive_activity']['count']} event(s) require validation.")
    if not concerns:
        concerns = None

    top_event = stats["top_event_names"][0][0] if stats["top_event_names"] else "N/A"
    return {
        "executive_summary": f"Athena-AI reviewed {stats['total_events']} AWS events for this reporting period. The calculated cloud risk rating is {stats['risk_rating']} based on IAM changes, failed API calls, root activity, destructive actions, and security findings. The most frequent observed AWS event is {top_event}.",
        "trend_summary": "Trend analysis compares the current period with the previous equivalent period. Increases in IAM changes, failed API calls, root activity, destructive actions, GuardDuty findings, or Inspector findings should receive priority review.",
        "key_findings": [
            f"CloudTrail events: {stats['sections']['cloudtrail']['count']}",
            f"GuardDuty events: {stats['sections']['guardduty']['count']}",
            f"Inspector2 events: {stats['sections']['inspector2']['count']}",
            f"WAF events: {stats['sections']['waf']['count']}",
            f"IAM changes: {stats['sections']['iam_changes']['count']}",
        ],
        "threat_landscape": "The main AWS risk areas in the observed data are identity and access changes, failed API activity, root usage, destructive operations, GuardDuty detections, Inspector findings, and suspicious web traffic.",
        "critical_concerns": concerns,
        "recommendations": [r["recommendation"] for r in get_aws_recommendations(stats)[:5]],
        "positive_observations": ["No high-priority AWS risk indicators were calculated from the available data."] if stats["risk_rating"] == "Low" else None,
        "overall_risk_rating": stats["risk_rating"],
    }


def get_ai_aws_summary(stats, report_type, time_from, time_to):
    if not LLM_ENABLED:
        log("LLM disabled; using fallback Athena AI analysis")
        return fallback_ai_analysis(stats)
    if not LLM_API_KEY:
        log("LLM_API_KEY is not set; using fallback Athena AI analysis")
        return fallback_ai_analysis(stats)
    try:
        import requests
        prompt = f"""Senior cloud security analyst for Athena SOC. Generate a {report_type} Amazon Web Services cloud health and security report for {time_from} to {time_to}.

METRICS:
Total AWS events: {stats['total_events']}
Risk rating: {stats['risk_rating']} / score {stats['risk_score']}
Sources: {stats['sources']}
Accounts: {stats['accounts']}
Regions: {stats['regions']}
Top AWS event names: {stats['top_event_names'][:10]}
Top AWS services: {stats['top_event_sources'][:10]}

AWS SECURITY SECTIONS:
CloudTrail events: {stats['sections']['cloudtrail']['count']}, methods={stats['sections']['cloudtrail']['methods'][:5]}
GuardDuty events: {stats['sections']['guardduty']['count']}, severity={stats['sections']['guardduty']['severity'][:5]}
Inspector2 events: {stats['sections']['inspector2']['count']}, severity={stats['sections']['inspector2']['severity'][:5]}
WAF events: {stats['sections']['waf']['count']}, actions={stats['sections']['waf']['actions'][:5]}
IAM changes: {stats['sections']['iam_changes']['count']}, methods={stats['sections']['iam_changes']['methods'][:5]}
Failed API calls: {stats['sections']['failed_api_calls']['count']}, errors={stats['sections']['failed_api_calls']['errors'][:5]}
Root activity: {stats['sections']['root_activity']['count']}, methods={stats['sections']['root_activity']['methods'][:5]}
Destructive activity: {stats['sections']['destructive_activity']['count']}, methods={stats['sections']['destructive_activity']['methods'][:5]}

Return ONLY valid JSON:
{{
  "executive_summary": "2-3 short paragraphs with specific numbers and risk interpretation",
  "trend_summary": "Trend and priority analysis",
  "key_findings": ["3-5 findings with numbers"],
  "threat_landscape": "AWS cloud threat/risk pattern summary",
  "critical_concerns": ["Immediate items"] or null,
  "recommendations": ["3-5 actionable AWS recommendations"],
  "positive_observations": ["Positive observations"] or null,
  "overall_risk_rating": "Low/Medium/High/Critical"
}}
"""
        payload = {
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": "You are a senior AWS cloud security analyst. Return only valid JSON. Do not hallucinate. If data is unavailable, say unavailable."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }
        log(f"Calling LLM at {LLM_CHAT_URL} for AWS Athena AI analysis...")
        response = requests.post(LLM_CHAT_URL, headers=build_llm_headers(), json=payload, timeout=(10, 180))
        if response.status_code == 200:
            result = response.json()
            choice = result["choices"][0]
            parsed = _parse_llm_json(choice["message"].get("content", ""), choice.get("finish_reason"))
            return parsed if parsed else fallback_ai_analysis(stats)
        log(f"LLM API error: {response.status_code} - {response.text}; using fallback Athena AI analysis")
        return fallback_ai_analysis(stats)
    except Exception as e:
        log(f"Error getting Athena AI AWS analysis: {e}; using fallback")
        return fallback_ai_analysis(stats)


def format_comparison_html(comparison_key, stats, colors):
    if not stats.get("comparisons") or comparison_key not in stats["comparisons"]:
        return '<div style="color:' + colors['text_light'] + ';font-size:11px;margin-bottom:8px;visibility:hidden;height:14px;">&nbsp;</div>'
    comp = stats["comparisons"][comparison_key]
    change_type = comp.get("change_type", "no change")
    change_pct = comp.get("change_pct", 0)
    if change_type == "decrease":
        color, arrow = colors["success"], "↓"
    elif change_type == "increase":
        color, arrow = colors["danger"], "↑"
    else:
        color, arrow = colors["text_light"], "→"
    return f'<div style="color:{color};font-size:11px;margin-bottom:8px;font-weight:500;">{arrow} {change_pct:.1f}% vs previous period</div>'


def _risk_color(risk):
    return {"Critical": "#b91c1c", "High": "#fb8c00", "Medium": "#facc15", "Low": "#22c55e"}.get(str(risk).capitalize(), "#6b7280")


def _section_title(name):
    return {
        "cloudtrail": "CloudTrail Activity",
        "guardduty": "GuardDuty Findings",
        "inspector2": "Inspector2 Findings",
        "waf": "WAF Activity",
        "iam_changes": "IAM Changes",
        "failed_api_calls": "Failed API Calls",
        "root_activity": "Root Account Activity",
        "destructive_activity": "Destructive / Service-Impacting Activity",
    }.get(name, name.replace("_", " ").title())


def build_ai_section(ai_analysis, colors):
    risk = str(ai_analysis.get("overall_risk_rating", "")).capitalize()
    risk_color = _risk_color(risk)
    ai_section = f"""
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f9ff;border:1px solid #c7d2fe;border-radius:6px;margin:24px 0;">
        <tr>
            <td style="background:#0d47a1;padding:12px 20px;border-top-left-radius:6px;border-top-right-radius:6px;">
            <h2 style="margin:0;color:#fff;font-size:16px;font-weight:600;">Athena AI: AWS Cloud Analysis</h2>
            </td>
        </tr>
        <tr><td style="padding:20px;color:#1e293b;font-size:14px;line-height:1.6;">
    """
    if risk:
        ai_section += f"""
            <div style='margin-top:6px;margin-bottom:24px;'>
                <span style='background:{risk_color};color:#fff;padding:4px 10px;border-radius:12px;font-size:13px;font-weight:600;'>Overall Risk Rating: {html.escape(risk)}</span>
            </div>
        """
    ai_section += f"""
        <div style="margin-bottom:16px;"><strong>Executive Summary:</strong><p style="margin:4px 0;">{html.escape(ai_analysis.get('executive_summary', 'No executive summary available.'))}</p></div>
    """
    if ai_analysis.get("trend_summary"):
        ai_section += f"""
        <div style='margin-bottom:16px;background:#fefce8;padding:12px;border-radius:4px;border-left:4px solid #ca8a04;'>
            <strong style='color:#854d0e;'>Trend Summary:</strong><p style='margin:6px 0;color:#1e293b;'>{html.escape(ai_analysis.get('trend_summary', ''))}</p>
        </div>"""
    if ai_analysis.get("key_findings"):
        items = ''.join([f"<li style='margin:4px 0;'>{html.escape(str(x))}</li>" for x in ai_analysis["key_findings"]])
        ai_section += f"<div style='margin-bottom:16px;'><strong>Key Findings:</strong><ul style='margin:6px 0;padding-left:20px;'>{items}</ul></div>"
    if ai_analysis.get("threat_landscape"):
        ai_section += f"""
        <div style='margin-bottom:16px;background:#eff6ff;padding:12px;border-radius:4px;border-left:4px solid #2563eb;'>
            <strong style='color:#1e40af;'>Threat Landscape:</strong><p style='margin:6px 0;color:#1e293b;'>{html.escape(ai_analysis.get('threat_landscape', ''))}</p>
        </div>"""
    if ai_analysis.get("critical_concerns"):
        items = ''.join([f"<li style='margin:4px 0;color:#dc2626;'><strong>{html.escape(str(x))}</strong></li>" for x in ai_analysis["critical_concerns"]])
        ai_section += f"<div style='margin-bottom:16px;background:#fef2f2;padding:12px;border-radius:4px;border-left:4px solid #dc2626;'><strong style='color:#dc2626;'>Critical Concerns:</strong><ul style='margin:6px 0;padding-left:20px;'>{items}</ul></div>"
    if ai_analysis.get("recommendations"):
        items = ''.join([f"<li style='margin:4px 0;'>{html.escape(str(x))}</li>" for x in ai_analysis["recommendations"]])
        ai_section += f"<div style='margin-bottom:16px;'><strong>Recommendations:</strong><ol style='margin:6px 0;padding-left:20px;'>{items}</ol></div>"
    if ai_analysis.get("positive_observations"):
        items = ''.join([f"<li style='margin:4px 0;color:#166534;'>{html.escape(str(x))}</li>" for x in ai_analysis["positive_observations"]])
        ai_section += f"<div style='margin-bottom:16px;background:#f0fdf4;padding:12px;border-radius:4px;border-left:4px solid #22c55e;'><strong style='color:#16a34a;'>Positive Observations:</strong><ul style='margin:6px 0;padding-left:20px;'>{items}</ul></div>"
    ai_section += "</td></tr></table>"
    return ai_section


def _section_detail(sec, key):
    if key in ["cloudtrail", "iam_changes", "failed_api_calls", "root_activity", "destructive_activity"]:
        return sec.get("methods", [])
    if key in ["guardduty", "inspector2"]:
        return sec.get("severity", []) or sec.get("types", [])
    if key == "waf":
        return sec.get("actions", [])
    return []


def _linked_text(label, url, color, font_size="14px", font_weight="600"):
    safe_label = html.escape(str(label))
    if not url:
        return f'<span style="color:{color};font-weight:{font_weight};font-size:{font_size};">{safe_label}</span>'
    return f'<a href="{html.escape(url, quote=True)}" style="color:{color};text-decoration:none;font-weight:{font_weight};font-size:{font_size};">{safe_label}</a>'


def _view_link(label, url, color):
    if not url:
        return ""
    return f'<a href="{html.escape(url, quote=True)}" style="color:{color};text-decoration:none;font-size:12px;font-weight:500;">{html.escape(label)} →</a>'


def build_section_rows(stats, colors, time_from, time_to):
    rows = ""
    order = ["cloudtrail", "guardduty", "inspector2", "waf", "iam_changes", "failed_api_calls", "root_activity", "destructive_activity"]
    for i, key in enumerate(order, 1):
        sec = stats["sections"][key]
        detail = _section_detail(sec, key)
        detail_text = ", ".join([f"{m} ({c})" for m, c in detail[:3]]) or "No detail data"
        title = _section_title(key)
        section_url = build_dashboard_url(time_from, time_to)
        if key in ["cloudtrail", "guardduty", "inspector2", "waf"]:
            section_url = build_dashboard_url(time_from, time_to, [{"type": "phrase", "field": "data.aws.source", "value": key}])
        elif sec.get("methods"):
            section_url = build_dashboard_url(time_from, time_to, [{"type": "phrase", "field": "data.aws.eventName", "value": sec["methods"][0][0]}])
        count_color = colors["danger"] if key in ["iam_changes", "failed_api_calls", "root_activity", "destructive_activity"] and sec["count"] > 0 else colors["primary"]
        title_html = _linked_text(title, section_url, colors["primary"])
        rows += f"""
        <tr style="background:{'#fafafa' if i % 2 == 0 else '#fff'};">
            <td style="padding:14px 16px;border-bottom:1px solid {colors['border']};font-size:14px;color:{colors['text']};font-weight:600;">{i}</td>
            <td style="padding:14px 16px;border-bottom:1px solid {colors['border']};">{title_html}</td>
            <td style="padding:14px 16px;border-bottom:1px solid {colors['border']};text-align:right;"><span style="background:{count_color};color:#fff;padding:5px 10px;border-radius:4px;font-weight:700;font-size:13px;display:inline-block;min-width:40px;text-align:center;">{sec['count']}</span></td>
            <td style="padding:14px 16px;border-bottom:1px solid {colors['border']};font-size:12px;color:{colors['text']};line-height:1.5;">{html.escape(detail_text)}</td>
        </tr>"""
    return rows


def build_simple_table_rows(items, colors, field, time_from, time_to):
    rows = ""
    for i, (name, count) in enumerate(items[:10], 1):
        url = build_dashboard_url(time_from, time_to, [{"type": "phrase", "field": field, "value": name}]) if name != "UNKNOWN" else build_dashboard_url(time_from, time_to)
        name_html = _linked_text(name, url, colors["primary"], font_size="13px", font_weight="500")
        rows += f"""
        <tr style="background:{'#fafafa' if i % 2 == 0 else '#fff'};">
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};font-weight:600;color:{colors['text']};">{i}</td>
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};">{name_html}</td>
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};text-align:right;font-weight:700;color:{colors['text']};">{count}</td>
        </tr>"""
    return rows


def build_recommendation_rows(recommendations, colors):
    rows = ""
    for i, rec in enumerate(recommendations, 1):
        pr = rec["priority"]
        pr_color = colors["danger"] if pr == "High" else colors["warning"] if pr == "Medium" else colors["success"]
        rows += f"""
        <tr style="background:{'#fafafa' if i % 2 == 0 else '#fff'};">
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};font-size:13px;color:{colors['text']};font-weight:600;">{html.escape(rec['area'])}</td>
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};text-align:center;"><span style="background:{pr_color};color:#fff;padding:4px 10px;border-radius:4px;font-size:12px;font-weight:600;">{html.escape(pr)}</span></td>
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};font-size:13px;color:{colors['text']};line-height:1.5;">{html.escape(rec['recommendation'])}</td>
            <td style="padding:12px 16px;border-bottom:1px solid {colors['border']};font-size:13px;color:{colors['text_light']};line-height:1.5;">{html.escape(rec['benefit'])}</td>
        </tr>"""
    return rows


def build_html_report(report_type, time_from, time_to, stats, ai_analysis):
    from_date = datetime.fromisoformat(time_from.replace('Z', '+00:00')).strftime('%B %d, %Y')
    to_date = datetime.fromisoformat(time_to.replace('Z', '+00:00')).strftime('%B %d, %Y')
    colors = {
        "primary": "#1e40af", "secondary": "#64748b", "success": "#059669", "warning": "#d97706",
        "danger": "#dc2626", "info": "#0284c7", "light": "#f8fafc", "dark": "#1e293b",
        "border": "#e2e8f0", "text": "#374151", "text_light": "#6b7280"
    }

    all_events_url = build_dashboard_url(time_from, time_to)
    cloudtrail_url = build_dashboard_url(time_from, time_to, [{"type": "phrase", "field": "data.aws.source", "value": "cloudtrail"}])
    guardduty_url = build_dashboard_url(time_from, time_to, [{"type": "phrase", "field": "data.aws.source", "value": "guardduty"}])
    inspector_url = build_dashboard_url(time_from, time_to, [{"type": "phrase", "field": "data.aws.source", "value": "inspector2"}])

    total_view_html = _view_link("View All", all_events_url, colors["primary"])
    cloudtrail_view_html = _view_link("View Details", cloudtrail_url, colors["info"])
    guardduty_view_html = _view_link("View Details", guardduty_url, colors["warning"])
    inspector_view_html = _view_link("View Details", inspector_url, colors["danger"])

    total_comparison_html = format_comparison_html('total_events', stats, colors)
    cloudtrail_comparison_html = format_comparison_html('cloudtrail', stats, colors)
    guardduty_comparison_html = format_comparison_html('guardduty', stats, colors)
    inspector_comparison_html = format_comparison_html('inspector2', stats, colors)

    ai_section = build_ai_section(ai_analysis, colors)
    section_rows = build_section_rows(stats, colors, time_from, time_to)
    source_rows = build_simple_table_rows(stats["sources"], colors, "data.aws.source", time_from, time_to)
    event_rows = build_simple_table_rows(stats["top_event_names"], colors, "data.aws.eventName", time_from, time_to)
    service_rows = build_simple_table_rows(stats["top_event_sources"], colors, "data.aws.eventSource", time_from, time_to)
    region_rows = build_simple_table_rows(stats["regions"], colors, "data.aws.region", time_from, time_to)
    recommendation_rows = build_recommendation_rows(get_aws_recommendations(stats), colors)

    html_output = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <!--[if mso]>
    <style type="text/css">
        body, table, td {{font-family: Arial, sans-serif !important;}}
    </style>
    <![endif]-->
</head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:{colors['light']};width:100%;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{colors['light']};margin:0;padding:0;">
        <tr><td align="center" style="padding:0;">
            <div style="background:#0d47a1;color:#fff;padding:12px 18px;font-size:18px;font-weight:700;">
                {ATHENA_NAME} — {report_type.title()} AWS Cloud Health Report
                <div style="font-size:12px;font-weight:400;opacity:0.95;color:#ffffff !important;">Tenant: {html.escape(TENANT_NAME)}</div>
                <div style="font-size:12px;font-weight:400;opacity:0.95;color:#ffffff;margin-top:4px;">📅 {from_date} — {to_date}</div>
            </div>
            <div style="padding:16px 18px;font-family:Arial,sans-serif;line-height:1.5;">
                <p style="margin:0 0 16px 0;">This is an automated AWS cloud health and security report generated by {ATHENA_NAME}.</p>

                <!-- Quick Stats -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:32px;"><tr><td style="padding:0;"><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
                    <td width="25%" style="padding:8px;vertical-align:top;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid {colors['border']};border-radius:6px;height:160px;table-layout:fixed;"><tr><td style="padding:20px;text-align:center;height:160px;vertical-align:middle;"><div style="font-size:32px;font-weight:700;color:{colors['primary']};margin-bottom:4px;">{stats['total_events']}</div><div style="color:{colors['text_light']};font-size:12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Total AWS Events</div><div style="min-height:20px;margin-bottom:4px;">{total_comparison_html}</div>{total_view_html}</td></tr></table></td>
                    <td width="25%" style="padding:8px;vertical-align:top;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid {colors['border']};border-radius:6px;height:160px;table-layout:fixed;"><tr><td style="padding:20px;text-align:center;height:160px;vertical-align:middle;"><div style="font-size:32px;font-weight:700;color:{colors['info']};margin-bottom:4px;">{stats['sections']['cloudtrail']['count']}</div><div style="color:{colors['info']};font-size:12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">CloudTrail</div><div style="color:{colors['text_light']};font-size:11px;margin-bottom:4px;">AWS audit and API activity</div><div style="min-height:20px;margin-bottom:4px;">{cloudtrail_comparison_html}</div>{cloudtrail_view_html}</td></tr></table></td>
                    <td width="25%" style="padding:8px;vertical-align:top;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;height:160px;table-layout:fixed;"><tr><td style="padding:20px;text-align:center;height:160px;vertical-align:middle;"><div style="font-size:32px;font-weight:700;color:{colors['warning']};margin-bottom:4px;">{stats['sections']['guardduty']['count']}</div><div style="color:{colors['warning']};font-size:12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">GuardDuty</div><div style="color:{colors['text_light']};font-size:11px;margin-bottom:4px;">Threat detection findings</div><div style="min-height:20px;margin-bottom:4px;">{guardduty_comparison_html}</div>{guardduty_view_html}</td></tr></table></td>
                    <td width="25%" style="padding:8px;vertical-align:top;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;height:160px;table-layout:fixed;"><tr><td style="padding:20px;text-align:center;height:160px;vertical-align:middle;"><div style="font-size:32px;font-weight:700;color:{colors['danger']};margin-bottom:4px;">{stats['sections']['inspector2']['count']}</div><div style="color:{colors['danger']};font-size:12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Inspector2</div><div style="color:{colors['text_light']};font-size:11px;margin-bottom:4px;">Vulnerability findings</div><div style="min-height:20px;margin-bottom:4px;">{inspector_comparison_html}</div>{inspector_view_html}</td></tr></table></td>
                </tr></table></td></tr></table>

                {ai_section}

                <!-- AWS Security Coverage -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid {colors['border']};border-radius:6px;margin:24px 0;"><tr><td style="padding:24px;">
                    <h3 style="margin:0 0 16px 0;color:{colors['dark']};font-size:18px;font-weight:600;border-bottom:2px solid {colors['border']};padding-bottom:8px;">AWS Cloud Health Coverage</h3>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><thead><tr style="background:{colors['light']};"><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:60px;">#</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Section</th><th style="padding:12px 16px;text-align:right;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:90px;">Count</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Top Detail</th></tr></thead><tbody>{section_rows}</tbody></table>
                </td></tr></table>

                <!-- AWS Configuration Recommendations -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid {colors['border']};border-radius:6px;margin:24px 0;"><tr><td style="padding:24px;">
                    <h3 style="margin:0 0 16px 0;color:{colors['dark']};font-size:18px;font-weight:600;border-bottom:2px solid {colors['border']};padding-bottom:8px;">AWS Configuration Improvement Recommendations</h3>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><thead><tr style="background:{colors['light']};"><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:150px;">Area</th><th style="padding:12px 16px;text-align:center;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:90px;">Priority</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Recommendation</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Benefit</th></tr></thead><tbody>{recommendation_rows}</tbody></table>
                </td></tr></table>

                <!-- AWS Sources -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid {colors['border']};border-radius:6px;margin:24px 0;"><tr><td style="padding:24px;">
                    <h3 style="margin:0 0 16px 0;color:{colors['dark']};font-size:18px;font-weight:600;border-bottom:2px solid {colors['border']};padding-bottom:8px;">AWS Sources</h3>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><thead><tr style="background:{colors['light']};"><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:60px;">#</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Source</th><th style="padding:12px 16px;text-align:right;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:120px;">Events</th></tr></thead><tbody>{source_rows}</tbody></table>
                </td></tr></table>

                <!-- Top Events and Services -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid {colors['border']};border-radius:6px;margin:24px 0;"><tr><td style="padding:24px;">
                    <h3 style="margin:0 0 16px 0;color:{colors['dark']};font-size:18px;font-weight:600;border-bottom:2px solid {colors['border']};padding-bottom:8px;">Most Triggered AWS Events</h3>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><thead><tr style="background:{colors['light']};"><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:60px;">#</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Event</th><th style="padding:12px 16px;text-align:right;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:120px;">Count</th></tr></thead><tbody>{event_rows}</tbody></table>
                    <h3 style="margin:24px 0 16px 0;color:{colors['dark']};font-size:18px;font-weight:600;border-bottom:2px solid {colors['border']};padding-bottom:8px;">Top AWS Services</h3>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><thead><tr style="background:{colors['light']};"><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:60px;">#</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Service</th><th style="padding:12px 16px;text-align:right;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:120px;">Events</th></tr></thead><tbody>{service_rows}</tbody></table>
                    <h3 style="margin:24px 0 16px 0;color:{colors['dark']};font-size:18px;font-weight:600;border-bottom:2px solid {colors['border']};padding-bottom:8px;">AWS Regions</h3>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;"><thead><tr style="background:{colors['light']};"><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:60px;">#</th><th style="padding:12px 16px;text-align:left;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};">Region</th><th style="padding:12px 16px;text-align:right;font-size:12px;color:{colors['text_light']};text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid {colors['border']};width:120px;">Events</th></tr></thead><tbody>{region_rows}</tbody></table>
                </td></tr></table>
            </div>
            <div style="background:#f3f4f6;color:#333;padding:12px 18px;font-size:12px;">
                <p style="margin:2px 0 6px 0;"><strong>Athena Security Group</strong></p>
                <p style="margin:2px 0;">🌐 <a href="{ATHENA_WEBSITE}" style="color:#0d47a1;text-decoration:none;">Website</a> &nbsp;|&nbsp; 📄 <a href="{ATHENA_DOCS}" style="color:#0d47a1;text-decoration:none;">Docs</a> &nbsp;|&nbsp; 📧 <a href="mailto:{ATHENA_SUPPORT}" style="color:#0d47a1;text-decoration:none;">{ATHENA_SUPPORT}</a></p>
                <p style="margin:10px 0 0 0;">This automated {report_type} AWS report was generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %I:%M %p UTC')}. Do not reply to this email.</p>
            </div>
        </td></tr>
    </table>
</body>
</html>
"""
    return html_output


def build_plain_report(report_type, time_from, time_to, stats, ai_analysis):
    from_date = datetime.fromisoformat(time_from.replace('Z', '+00:00')).strftime('%B %d, %Y')
    to_date = datetime.fromisoformat(time_to.replace('Z', '+00:00')).strftime('%B %d, %Y')
    lines = []
    lines.append("=" * 80)
    lines.append(f"{ATHENA_NAME} - {report_type.upper()} AWS CLOUD HEALTH REPORT")
    lines.append("=" * 80)
    lines.append(f"Tenant: {TENANT_NAME}")
    lines.append(f"Period: {from_date} — {to_date}")
    lines.append("")
    lines.append("AWS EVENT SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total AWS Events: {stats['total_events']}")
    lines.append(f"Risk Rating: {stats['risk_rating']} (Score: {stats['risk_score']})")
    lines.append(f"CloudTrail Events: {stats['sections']['cloudtrail']['count']}")
    lines.append(f"GuardDuty Events: {stats['sections']['guardduty']['count']}")
    lines.append(f"Inspector2 Events: {stats['sections']['inspector2']['count']}")
    lines.append(f"WAF Events: {stats['sections']['waf']['count']}")
    lines.append(f"IAM Changes: {stats['sections']['iam_changes']['count']}")
    lines.append(f"Failed API Calls: {stats['sections']['failed_api_calls']['count']}")
    lines.append(f"Root Activity: {stats['sections']['root_activity']['count']}")
    lines.append(f"Destructive Activity: {stats['sections']['destructive_activity']['count']}")
    lines.append("")
    lines.append("ATHENA AI: AWS CLOUD ANALYSIS")
    lines.append("-" * 80)
    lines.append(ai_analysis.get("executive_summary", "No executive summary available."))
    lines.append(f"Overall Risk Rating: {ai_analysis.get('overall_risk_rating', 'N/A')}")
    if ai_analysis.get("key_findings"):
        lines.append("Key Findings:")
        for i, finding in enumerate(ai_analysis["key_findings"], 1):
            lines.append(f"  {i}. {finding}")
    if ai_analysis.get("critical_concerns"):
        lines.append("Critical Concerns:")
        for concern in ai_analysis["critical_concerns"]:
            lines.append(f"  - {concern}")
    if ai_analysis.get("recommendations"):
        lines.append("AI Recommendations:")
        for i, rec in enumerate(ai_analysis["recommendations"], 1):
            lines.append(f"  {i}. {rec}")
    lines.append("")
    lines.append("AWS CONFIGURATION IMPROVEMENT RECOMMENDATIONS")
    lines.append("-" * 80)
    for i, rec in enumerate(get_aws_recommendations(stats), 1):
        lines.append(f"{i}. [{rec['priority']}] {rec['area']}: {rec['recommendation']} Benefit: {rec['benefit']}")
    lines.append("")
    lines.append("MOST TRIGGERED AWS EVENTS")
    lines.append("-" * 80)
    for i, (event, count) in enumerate(stats["top_event_names"][:10], 1):
        lines.append(f"{i:2}. {event}: {count}")
    lines.append("")
    lines.append("=" * 80)
    lines.append(f"{ATHENA_NAME}")
    lines.append(f"Website: {ATHENA_WEBSITE}")
    lines.append(f"Support: {ATHENA_SUPPORT}")
    lines.append(f"This automated {report_type} AWS report was generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %I:%M %p UTC')}")
    lines.append("Do not reply to this email.")
    lines.append("=" * 80)
    return "\n".join(lines)


def send_email(recipients, subject, plain_body, html_body) -> bool:
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["To"] = ", ".join(recipients)
        msg["From"] = formataddr((f"{ATHENA_NAME} Reports", SMTP_FROM))
        msg.set_content(plain_body)
        msg.add_alternative(html_body, subtype="html")
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.ehlo()
        if SMTP_USE_TLS and not SMTP_USE_SSL:
            server.starttls()
            server.ehlo()
        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        log(f"AWS report sent successfully to {recipients}")
        return True
    except Exception as e:
        log(f"Error sending AWS report email: {e}")
        return False


def add_comparisons(stats, prev_stats):
    comparisons = {
        "total_events": {"current": stats["total_events"], "previous": prev_stats.get("total_events", 0)},
        "cloudtrail": {"current": stats["sections"]["cloudtrail"]["count"], "previous": prev_stats.get("sections", {}).get("cloudtrail", {}).get("count", 0)},
        "guardduty": {"current": stats["sections"]["guardduty"]["count"], "previous": prev_stats.get("sections", {}).get("guardduty", {}).get("count", 0)},
        "inspector2": {"current": stats["sections"]["inspector2"]["count"], "previous": prev_stats.get("sections", {}).get("inspector2", {}).get("count", 0)},
    }
    for key, val in comparisons.items():
        pct, change_type = calculate_percentage_change(val["current"], val["previous"])
        val["change_pct"] = pct
        val["change_type"] = change_type
    stats["comparisons"] = comparisons
    return stats


def generate_report(report_type, time_from, time_to, recipients):
    log(f"Generating {report_type} AWS report from {time_from} to {time_to}")
    aggs = query_aws_data(time_from, time_to)
    if not aggs:
        log("No AWS data found for the specified time range")
        return False
    stats = analyze_aws(aggs)
    if stats["total_events"] == 0:
        log("No AWS events found for the specified time range")
        return False
    prev_time_from, prev_time_to = calculate_previous_period(time_from, time_to, report_type)
    prev_aggs = query_aws_data(prev_time_from, prev_time_to)
    prev_stats = analyze_aws(prev_aggs) if prev_aggs else {"total_events": 0, "sections": {}}
    stats = add_comparisons(stats, prev_stats)
    stats["previous_period"] = {"from": prev_time_from, "to": prev_time_to}
    ai_analysis = get_ai_aws_summary(stats, report_type, time_from, time_to)
    subject_date = datetime.fromisoformat(time_from.replace('Z', '+00:00')).strftime('%b %d, %Y')
    subject = f"[{TENANT_NAME}] Athena SOC {report_type.title()} AWS Cloud Health Report - {subject_date}"
    html_body = build_html_report(report_type, time_from, time_to, stats, ai_analysis)
    plain_body = build_plain_report(report_type, time_from, time_to, stats, ai_analysis)
    return send_email(recipients, subject, plain_body, html_body)


def main(args):
    if not REPORT_AWS_ENABLED:
        log("REPORT_AWS_ENABLED=false; skipping AWS report")
        return
    log("# Starting AWS report generation")
    if len(args) < 2:
        log("Usage: reports_aws.py <daily|weekly|monthly|custom> [recipients] [start_time] [end_time]")
        return
    report_type = args[1].lower()
    now = datetime.now(timezone.utc)
    recipients = SMTP_RECIPIENT
    if report_type == "daily":
        time_to = now.isoformat().replace("+00:00", "Z")
        time_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    elif report_type == "weekly":
        time_to = now.isoformat().replace("+00:00", "Z")
        time_from = (now - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    elif report_type == "monthly":
        time_to = now.isoformat().replace("+00:00", "Z")
        time_from = (now - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    elif report_type == "custom":
        if len(args) < 5:
            log("Custom report requires: reports_aws.py custom <recipients_optional_ignored> <start_time> <end_time>")
            return
        time_from = args[3]
        time_to = args[4]
    else:
        log(f"Unknown report type: {report_type}")
        return
    log(f"Generating {report_type} AWS report from {time_from} to {time_to}")
    log(f"Recipients: {recipients}")
    try:
        generate_report(report_type, time_from, time_to, recipients)
        log("AWS report generation completed successfully")
    except Exception as e:
        log(f"Error generating AWS report: {e}")
        import traceback
        log(traceback.format_exc())


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        log(f"Unhandled exception: {e}")
        import traceback
        log(traceback.format_exc())
        raise
