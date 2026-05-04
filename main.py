from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from datetime import datetime
import io, csv, json, os

from aws_scanner.iam_check import check_iam_mfa
from aws_scanner.s3_check import check_s3_buckets
from aws_scanner.ec2_check import check_ec2_security_groups
from aws_scanner.cloudtrail_check import check_cloudtrail
from aws_scanner.compliance import calculate_compliance
from routes.auth import router as auth_router
from auth_cognito import verify_token, require_admin, require_admin_or_auditor

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

app.include_router(auth_router)

SCAN_HISTORY_FILE = "scan_history.json"
latest_scan_cache = None


def severity_rank(severity):
    return {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "None": 4,
    }.get(severity, 99)


def recommendation_link(service):
    return {
        "IAM": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html",
        "S3": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access.html",
        "EC2": "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
        "CloudTrail": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
    }.get(service, "#")


def enrich_results(results):
    for r in results:
        r["recommendation_link"] = recommendation_link(r.get("service"))
    return results


def group_and_sort(results):
    grouped = {}
    for r in results:
        grouped.setdefault(r["service"], []).append(r)

    for service in grouped:
        grouped[service].sort(key=lambda x: severity_rank(x.get("severity", "None")))

    return grouped


def flatten(grouped):
    flat = []
    for service in ["IAM", "S3", "EC2", "CloudTrail"]:
        flat.extend(grouped.get(service, []))
    return flat


def load_history():
    if not os.path.exists(SCAN_HISTORY_FILE):
        return []

    try:
        with open(SCAN_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_history(data):
    with open(SCAN_HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def compare(old, new):
    old_set = {(r["service"], r["resource"], r["issue"]) for r in old}
    new_set = {(r["service"], r["resource"], r["issue"]) for r in new}

    return {
        "fixed": len(old_set - new_set),
        "new": len(new_set - old_set)
    }


def run_scan_logic():
    print("Starting IAM scan...")
    iam = check_iam_mfa()
    print("IAM scan finished.")

    print("Starting S3 scan...")
    s3 = check_s3_buckets()
    print("S3 scan finished.")

    print("Starting EC2 scan...")
    ec2 = check_ec2_security_groups()
    print("EC2 scan finished.")

    print("Starting CloudTrail scan...")
    cloudtrail = check_cloudtrail()
    print("CloudTrail scan finished.")

    results = enrich_results(iam + s3 + ec2 + cloudtrail)

    grouped = group_and_sort(results)
    sorted_results = flatten(grouped)

    compliance = calculate_compliance(sorted_results)

    history = load_history()
    prev = history[-1] if history else None

    improvement = "N/A"
    comparison = {"fixed": 0, "new": 0}

    if prev:
        old_score = prev.get("compliance_summary", {}).get("compliance_score", 0)
        new_score = compliance.get("compliance_score", 0)

        improvement = round(new_score - old_score, 2)
        comparison = compare(prev.get("results", []), sorted_results)

    

    scan = {
        "scan_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "results": sorted_results,
        "grouped_results": grouped,
        "compliance_summary": compliance,
        "total_results": len(sorted_results),
        "improvement_percentage": improvement,
        "comparison": comparison,
    }

    history.append(scan)
    save_history(history)

    print("Full scan finished successfully.")
    return scan


@app.get("/")
def home():
    return {"message": "BCDR running"}


@app.get("/me")
def get_me(user=Depends(verify_token)):
    return {"user": user}


@app.get("/scan")
def full_scan(user=Depends(require_admin)):
    global latest_scan_cache
    latest_scan_cache = run_scan_logic()
    return latest_scan_cache


@app.get("/findings")
def findings(user=Depends(require_admin_or_auditor)):
    global latest_scan_cache

    if not latest_scan_cache:
        history = load_history()

        if not history:
            raise HTTPException(status_code=404, detail="No scan available")

        latest_scan_cache = history[-1]

    return latest_scan_cache


@app.get("/scan-history")
def history(user=Depends(require_admin_or_auditor)):
    return {"history": load_history()[::-1]}


@app.get("/scan-history/{scan_id}")
def get_scan_by_id(scan_id: str, user=Depends(require_admin_or_auditor)):
    history = load_history()

    for item in history:
        if item.get("scan_id") == scan_id:
            return item

    return {"message": "Scan not found"}


@app.get("/export")
def export(user=Depends(require_admin_or_auditor)):
    global latest_scan_cache

    if not latest_scan_cache:
        history = load_history()

        if not history:
            raise HTTPException(status_code=404, detail="No scan available")

        latest_scan_cache = history[-1]

    filename = datetime.now().strftime("%Y%m%d_%H%M%S")

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "scan_date", "service", "resource",
        "issue", "severity", "status", "recommendation"
    ])

    for r in latest_scan_cache["results"]:
        writer.writerow([
            latest_scan_cache["scan_date"],
            r.get("service", ""),
            r.get("resource", ""),
            r.get("issue", ""),
            r.get("severity", ""),
            r.get("status", ""),
            r.get("recommendation", "")
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=cloud_security_report_{filename}.csv"
        }
    )