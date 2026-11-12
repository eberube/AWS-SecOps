#!/usr/bin/env python3
"""Find (and optionally delete) what `cdk destroy --all` can leave behind.

Dry run by default. Nothing is deleted without --apply.

  python scripts/cleanup_leftovers.py --region us-east-1                 # report only
  python scripts/cleanup_leftovers.py --region us-east-1 --apply         # empty/delete leftovers
  python scripts/cleanup_leftovers.py --region us-east-1 --apply --include-bootstrap

Handles:
  * S3 buckets whose stack deletion failed with BucketNotEmpty (late S3 access-log delivery)
  * CloudWatch log groups created at runtime by CDK custom-resource Lambdas (/aws/lambda/<project>-*)
  * Optional: the CDKToolkit bootstrap stack, its retained staging bucket and ECR repository
Reports (never deletes):
  * KMS keys pending deletion, account-level settings intentionally left enabled
"""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import ClientError


def empty_and_delete_bucket(s3, name: str, apply: bool) -> None:
    print(f"  bucket {name}")
    if not apply:
        return
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=name):
        objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                   for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objects), 1000):
            s3.delete_objects(Bucket=name, Delete={"Objects": objects[i:i + 1000], "Quiet": True})
    s3.delete_bucket(Bucket=name)
    print("    emptied and deleted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", default="secure-foundation")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--apply", action="store_true", help="actually delete (default is a dry run)")
    parser.add_argument("--include-bootstrap", action="store_true", help="also remove the CDKToolkit stack")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    s3 = session.client("s3")
    logs = session.client("logs")
    cfn = session.client("cloudformation")
    kms = session.client("kms")
    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"[{mode}] account {account}, region {args.region}, project {args.project}\n")

    # Refuse to clean up while the project's stacks still exist, except ones stuck in DELETE_FAILED.
    live = []
    for page in cfn.get_paginator("list_stacks").paginate():
        for s in page["StackSummaries"]:
            if s["StackName"].startswith(f"{args.project}-") and s["StackStatus"] not in ("DELETE_COMPLETE", "DELETE_FAILED"):
                live.append(f'{s["StackName"]} ({s["StackStatus"]})')
    if live:
        print("These stacks still exist; run `cdk destroy --all` first:\n  " + "\n  ".join(live))
        return 1

    print("S3 buckets:")
    for b in s3.list_buckets()["Buckets"]:
        if b["Name"].startswith(f"{args.project}-"):
            empty_and_delete_bucket(s3, b["Name"], args.apply)

    print("CloudWatch log groups:")
    for prefix in (f"/aws/lambda/{args.project}-", f"/{args.project}/"):
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
            for lg in page["logGroups"]:
                print(f"  {lg['logGroupName']}")
                if args.apply:
                    logs.delete_log_group(logGroupName=lg["logGroupName"])

    if args.include_bootstrap:
        print("CDK bootstrap:")
        try:
            cfn.describe_stacks(StackName="CDKToolkit")
            print("  stack CDKToolkit")
            if args.apply:
                cfn.delete_stack(StackName="CDKToolkit")
                cfn.get_waiter("stack_delete_complete").wait(StackName="CDKToolkit")
        except ClientError:
            pass
        for b in s3.list_buckets()["Buckets"]:
            if b["Name"].startswith("cdk-") and b["Name"].endswith(f"-assets-{account}-{args.region}"):
                empty_and_delete_bucket(s3, b["Name"], args.apply)
        ecr = session.client("ecr")
        for repo in ecr.describe_repositories().get("repositories", []):
            if repo["repositoryName"].startswith("cdk-") and "container-assets" in repo["repositoryName"]:
                print(f"  ecr {repo['repositoryName']}")
                if args.apply:
                    ecr.delete_repository(repositoryName=repo["repositoryName"], force=True)

    print("\nKMS keys pending deletion (deleted automatically after the 7-day window):")
    for page in kms.get_paginator("list_keys").paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if meta.get("KeyState") == "PendingDeletion" and meta.get("KeyManager") == "CUSTOMER":
                print(f"  {meta['KeyId']} deletes on {meta.get('DeletionDate')}")

    print("\nIntentionally retained account settings (secure, free): S3 account-level Block Public Access,"
          " EBS encryption by default. Disable manually only if required.")
    if not args.apply:
        print("\nDry run only. Re-run with --apply to delete the items listed above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
