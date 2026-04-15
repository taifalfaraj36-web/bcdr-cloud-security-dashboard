from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from datetime import datetime
import io
import csv

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
)

app.include_router(auth_router)


def collect_all_results():
    iam_results = check_iam_mfa()
    s3_results = check_s3_buckets()
    ec2_results = check_ec2_security_groups()
    cloudtrail_results = check_cloudtrail()

    all_results = iam_results + s3_results + ec2_results + cloudtrail_results
    compliance = calculate_compliance(all_results)
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return all_results, compliance, scan_date


@app.get("/")
def home():
    return {"message": "BCDR Cloud Security Dashboard is running"}


@app.get("/me")
def get_me(user=Depends(verify_token)):
    return {
        "message": "Token is valid",
        "user": user
    }


@app.get("/scan/iam")
def run_iam_scan(user=Depends(require_admin)):
    results = check_iam_mfa()
    return {
        "scan": "IAM MFA check",
        "requested_by": user.get("username"),
        "groups": user.get("cognito:groups", []),
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_results": len(results),
        "results": results
    }


@app.get("/scan/s3")
def run_s3_scan(user=Depends(require_admin)):
    results = check_s3_buckets()
    return {
        "scan": "S3 bucket check",
        "requested_by": user.get("username"),
        "groups": user.get("cognito:groups", []),
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_results": len(results),
        "results": results
    }


@app.get("/scan/ec2")
def run_ec2_scan(user=Depends(require_admin)):
    results = check_ec2_security_groups()
    return {
        "scan": "EC2 security group check",
        "requested_by": user.get("username"),
        "groups": user.get("cognito:groups", []),
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_results": len(results),
        "results": results
    }


@app.get("/scan/cloudtrail")
def run_cloudtrail_scan(user=Depends(require_admin)):
    results = check_cloudtrail()
    return {
        "scan": "CloudTrail logging check",
        "requested_by": user.get("username"),
        "groups": user.get("cognito:groups", []),
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_results": len(results),
        "results": results
    }


@app.get("/scan")
def run_full_scan(user=Depends(require_admin)):
    all_results, compliance, scan_date = collect_all_results()

    return {
        "scan": "Full cloud scan",
        "requested_by": user.get("username"),
        "groups": user.get("cognito:groups", []),
        "scan_date": scan_date,
        "total_results": len(all_results),
        "compliance_summary": compliance,
        "results": all_results
    }


@app.get("/findings")
def get_findings(user=Depends(require_admin_or_auditor)):
    all_results, compliance, scan_date = collect_all_results()

    return {
        "message": "Authorized access to findings",
        "requested_by": user.get("username"),
        "groups": user.get("cognito:groups", []),
        "scan_date": scan_date,
        "total_results": len(all_results),
        "compliance_summary": compliance,
        "results": all_results
    }


@app.get("/export")
def export_csv(user=Depends(require_admin_or_auditor)):
    all_results, compliance, scan_date = collect_all_results()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "scan_date",
        "service",
        "resource",
        "issue",
        "severity",
        "status"
    ])

    for item in all_results:
        writer.writerow([
            scan_date,
            item.get("service", ""),
            item.get("resource", ""),
            item.get("issue", ""),
            item.get("severity", ""),
            item.get("status", "")
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cloud_security_report.csv"}
    )