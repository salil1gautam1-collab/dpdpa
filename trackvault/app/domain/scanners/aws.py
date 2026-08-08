"""AWS posture connector — read-only, consent-gated, standard library only.

Implements AWS Signature Version 4 by hand (no boto3) and runs the checks
specified in docs/INFRA-SCANNER-SPEC.md against the client-supplied,
least-privilege credentials (recommend: dedicated IAM user with the
`SecurityAudit` managed policy):

  aws_credentials_valid   STS GetCallerIdentity
  aws_s3_public_access    S3Control account Public Access Block
  aws_s3_encryption       per-bucket default encryption
  aws_cloudtrail          trails exist and are logging (audit trail, Rule 6(1)(c))
  aws_sg_exposure         security groups open to the world on non-web ports
  aws_rds_encryption      RDS storage encryption at rest
  aws_iam_hygiene         root MFA + access-key age

Every API call is a read. Nothing is modified. Secrets are used in-memory for
signing and never written to findings or logs.
"""
from __future__ import annotations

import hashlib
import hmac
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from ..evidence import make_evidence

TIMEOUT = 25
UA = "DPDPA-Sentinel/0.1 (read-only posture scan)"


# ------------------------------------------------------------- sigv4 core --

def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _request(service: str, region: str, host: str, method: str, path: str,
             query: dict, body: bytes, creds: dict) -> tuple[int, str]:
    """Signed HTTPS request. Returns (status, body_text). Raises nothing."""
    t = datetime.now(timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()

    headers = {"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    if body:
        headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8"
    signed_list = sorted(headers)
    canonical_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in signed_list)
    signed_headers = ";".join(signed_list)
    canonical_qs = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted(query.items()))
    canonical = "\n".join([method, urllib.parse.quote(path, safe="/-_.~"), canonical_qs,
                           canonical_headers, signed_headers, payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    k = _hmac(("AWS4" + creds["secretAccessKey"]).encode("utf-8"), datestamp)
    k = _hmac(_hmac(_hmac(k, region), service), "aws4_request")
    signature = hmac.new(k, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth = (f"AWS4-HMAC-SHA256 Credential={creds['accessKeyId']}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    url = f"https://{host}{path}" + (f"?{canonical_qs}" if canonical_qs else "")
    req = urllib.request.Request(url, data=body or None, method=method)
    for hk, hv in headers.items():
        if hk != "host":
            req.add_header(hk, hv)
    req.add_header("Authorization", auth)
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(1_000_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as ex:
        return ex.code, ex.read(100_000).decode("utf-8", errors="replace")
    except Exception as ex:
        return 0, f"network-error: {type(ex).__name__}: {ex}"


def _query_api(service: str, region: str, host: str, action: str, version: str,
               creds: dict, extra: dict | None = None) -> tuple[int, str]:
    params = {"Action": action, "Version": version, **(extra or {})}
    body = urllib.parse.urlencode(sorted(params.items())).encode("utf-8")
    return _request(service, region, host, "POST", "/", {}, body, creds)


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _findall(xml_text: str, localname: str) -> list:
    """Namespace-agnostic element search; returns [] on parse failure."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    return [el for el in root.iter() if _local(el.tag) == localname]


def _err_code(xml_text: str) -> str:
    codes = _findall(xml_text, "Code")
    return codes[0].text if codes else (xml_text[:200] if xml_text else "unknown")


# ----------------------------------------------------------------- checks --

def run_checks(conn: dict) -> tuple[list, dict]:
    """conn = {"accessKeyId", "secretAccessKey", "region"}. Returns (findings, meta)."""
    creds = conn
    region = conn.get("region") or "ap-south-1"
    findings: list = []
    meta: dict = {"awsRegion": region}

    def finding(check_id, status, excerpt, note=""):
        findings.append({"webCheckId": check_id, "site": f"aws:{region}", "status": status,
                         "evidence": [make_evidence("aws-api", url=f"aws://{check_id}",
                                                    excerpt=excerpt, note=note)]})

    # 1. STS — validate credentials, get account id
    code, text = _query_api("sts", region, f"sts.{region}.amazonaws.com",
                            "GetCallerIdentity", "2011-06-15", creds)
    if code != 200:
        finding("aws_credentials_valid", "gap" if code in (403,) else "unknown",
                f"STS GetCallerIdentity failed (HTTP {code}): {_err_code(text)}",
                "credentials invalid, expired, or network blocked — all AWS checks skipped")
        return findings, meta
    account = (_findall(text, "Account") or [None])[0]
    account_id = account.text if account is not None else ""
    arn = (_findall(text, "Arn") or [None])[0]
    meta["awsAccount"] = account_id
    finding("aws_credentials_valid", "ok",
            f"connected to AWS account {account_id} as {arn.text if arn is not None else '?'}")

    # 2. Account-level S3 Public Access Block (s3control)
    code, text = _request("s3", region, f"{account_id}.s3-control.{region}.amazonaws.com",
                          "GET", "/v20180820/configuration/publicAccessBlock", {}, b"", creds)
    if code == 200:
        flags = {_local(el.tag): (el.text or "").lower() for el in _findall(text, "PublicAccessBlockConfiguration")[0]} \
            if _findall(text, "PublicAccessBlockConfiguration") else {}
        all_on = flags and all(v == "true" for v in flags.values())
        finding("aws_s3_public_access", "ok" if all_on else "partial",
                f"account Public Access Block: {flags or 'present but unparsed'}")
    elif "NoSuchPublicAccessBlockConfiguration" in text:
        finding("aws_s3_public_access", "gap",
                "no account-level S3 Public Access Block configured — buckets can be made public")
    else:
        finding("aws_s3_public_access", "unknown", f"HTTP {code}: {_err_code(text)}")

    # 3. S3 buckets + default encryption
    code, text = _request("s3", region, f"s3.{region}.amazonaws.com", "GET", "/", {}, b"", creds)
    buckets = [el.text for el in _findall(text, "Name")] if code == 200 else []
    meta["s3Buckets"] = len(buckets)
    if code != 200:
        finding("aws_s3_encryption", "unknown", f"ListBuckets failed HTTP {code}: {_err_code(text)}")
    elif not buckets:
        finding("aws_s3_encryption", "na", "no S3 buckets in account")
    else:
        enc, unenc, skipped = [], [], []
        for b in buckets[:40]:  # politeness cap
            c2, t2 = _request("s3", region, f"s3.{region}.amazonaws.com",
                              "GET", f"/{b}", {"encryption": ""}, b"", creds)
            if c2 == 200 and _findall(t2, "SSEAlgorithm"):
                enc.append(b)
            elif "ServerSideEncryptionConfigurationNotFoundError" in t2:
                unenc.append(b)
            else:
                skipped.append(f"{b}({_err_code(t2)})")
        status = "ok" if not unenc and enc else ("gap" if unenc and not enc else
                 "partial" if unenc else "unknown")
        finding("aws_s3_encryption", status,
                f"{len(enc)}/{len(buckets)} buckets have default encryption; "
                f"unencrypted: {unenc or 'none'}; unverifiable: {len(skipped)}",
                "buckets in other regions may appear unverifiable — re-run with that region")

    # 4. CloudTrail
    code, text = _query_api("cloudtrail", region, f"cloudtrail.{region}.amazonaws.com",
                            "DescribeTrails", "2013-11-01", creds)
    if code != 200:
        finding("aws_cloudtrail", "unknown", f"DescribeTrails HTTP {code}: {_err_code(text)}")
    else:
        names = [el.text for el in _findall(text, "Name")]
        if not names:
            finding("aws_cloudtrail", "gap", "no CloudTrail trails configured — no audit log of account activity")
        else:
            logging_on = []
            for n in names[:10]:
                c2, t2 = _query_api("cloudtrail", region, f"cloudtrail.{region}.amazonaws.com",
                                    "GetTrailStatus", "2013-11-01", creds, {"Name": n})
                if c2 == 200 and any((el.text or "").lower() == "true" for el in _findall(t2, "IsLogging")):
                    logging_on.append(n)
            finding("aws_cloudtrail", "ok" if logging_on else "gap",
                    f"trails: {names}; actively logging: {logging_on or 'NONE'}",
                    "verify retention >= 1 year per DPDP Rule 6 — retention lives in the trail's S3 bucket lifecycle")

    # 5. Security groups open to the world
    code, text = _query_api("ec2", region, f"ec2.{region}.amazonaws.com",
                            "DescribeSecurityGroups", "2016-11-15", creds)
    if code != 200:
        finding("aws_sg_exposure", "unknown", f"DescribeSecurityGroups HTTP {code}: {_err_code(text)}")
    else:
        exposed = []
        try:
            root = ET.fromstring(text)
            for sg in root.iter():
                if _local(sg.tag) != "item" or sg.find("./") is None:
                    continue
                gid = next((c.text for c in sg if _local(c.tag) == "groupId"), None)
                if not gid:
                    continue
                for perm in sg.iter():
                    if _local(perm.tag) != "item":
                        continue
                    cidrs = [c.text for c in perm.iter() if _local(c.tag) == "cidrIp"]
                    ports = [c.text for c in perm if _local(c.tag) in ("fromPort", "toPort")]
                    if "0.0.0.0/0" in cidrs and ports and not set(ports) <= {"80", "443"}:
                        exposed.append(f"{gid}:{'-'.join(ports)}")
        except ET.ParseError:
            pass
        exposed = sorted(set(exposed))[:20]
        finding("aws_sg_exposure", "gap" if exposed else "ok",
                f"security groups open to 0.0.0.0/0 on non-web ports: {exposed or 'none'}")

    # 6. RDS encryption
    code, text = _query_api("rds", region, f"rds.{region}.amazonaws.com",
                            "DescribeDBInstances", "2014-10-31", creds)
    if code != 200:
        finding("aws_rds_encryption", "unknown", f"DescribeDBInstances HTTP {code}: {_err_code(text)}")
    else:
        ids = [el.text for el in _findall(text, "DBInstanceIdentifier")]
        flags = [(el.text or "").lower() for el in _findall(text, "StorageEncrypted")]
        if not ids:
            finding("aws_rds_encryption", "na", "no RDS instances in this region")
        else:
            unenc = [i for i, f in zip(ids, flags) if f != "true"]
            finding("aws_rds_encryption", "ok" if not unenc else ("partial" if len(unenc) < len(ids) else "gap"),
                    f"{len(ids) - len(unenc)}/{len(ids)} RDS instances encrypted at rest; unencrypted: {unenc or 'none'}")

    # 7. IAM hygiene — root MFA + access-key age
    code, text = _query_api("iam", region, "iam.amazonaws.com", "GetAccountSummary", "2010-05-08", creds)
    root_mfa = None
    if code == 200:
        try:
            root = ET.fromstring(text)
            entries = [el for el in root.iter() if _local(el.tag) == "entry"]
            for en in entries:
                kv = {_local(c.tag): c.text for c in en}
                if kv.get("key") == "AccountMFAEnabled":
                    root_mfa = kv.get("value") == "1"
        except ET.ParseError:
            pass
    code2, text2 = _query_api("iam", region, "iam.amazonaws.com", "ListUsers", "2010-05-08", creds)
    old_keys = []
    if code2 == 200:
        users = [el.text for el in _findall(text2, "UserName")][:25]
        cutoff = datetime.now(timezone.utc).timestamp() - 90 * 86400
        for uname in users:
            c3, t3 = _query_api("iam", region, "iam.amazonaws.com", "ListAccessKeys",
                                "2010-05-08", creds, {"UserName": uname})
            for el in _findall(t3, "CreateDate"):
                try:
                    if datetime.fromisoformat(el.text.replace("Z", "+00:00")).timestamp() < cutoff:
                        old_keys.append(uname)
                        break
                except (ValueError, AttributeError):
                    pass
    if root_mfa is None and code2 != 200:
        finding("aws_iam_hygiene", "unknown",
                f"IAM checks unavailable (GetAccountSummary HTTP {code}, ListUsers HTTP {code2}) — "
                "grant SecurityAudit policy for full coverage")
    else:
        bad = (root_mfa is False)
        finding("aws_iam_hygiene", "gap" if bad else ("partial" if old_keys else "ok"),
                f"root MFA enabled: {root_mfa}; users with access keys older than 90 days: {sorted(set(old_keys)) or 'none'}")

    return findings, meta
