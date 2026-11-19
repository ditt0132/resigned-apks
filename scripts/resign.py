#!/usr/bin/env python3
"""Mirror upstream GitHub release APKs and re-sign them with a private key."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API_ROOT = "https://api.github.com"
USER_AGENT = "Mozilla/5.0 apk-resign/1.0"
APK_SUFFIX = ".apk"


class MirrorError(RuntimeError):
    pass


def slug(value: str) -> str:
    """Produce a stable lowercase filename/tag component."""
    value = value.lower().replace("+", "-plus-")
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"[-_.]{2,}", "-", value).strip("-._")
    return value or "item"


def normalize_for_match(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def github_repo(value: str) -> str:
    """Accept owner/repo or a GitHub HTTPS/SSH clone URL."""
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        owner, repo = value.split("/", 1)
        return f"{owner}/{repo.removesuffix('.git')}"
    if value.startswith("git@github.com:"):
        path = value.removeprefix("git@github.com:").removesuffix(".git").strip("/")
        if re.fullmatch(r"[^/]+/[^/]+", path):
            return path
    parsed = urlparse(value)
    if parsed.scheme in {"https", "http"} and parsed.netloc.lower() in {"github.com", "www.github.com"}:
        path = parsed.path.strip("/").removesuffix(".git")
        parts = path.split("/")
        if len(parts) == 2 and all(parts):
            return f"{parts[0]}/{parts[1]}"
    raise MirrorError(
        f"Unsupported repository '{value}'. Source repositories must be GitHub repos, "
        "written as owner/repo or https://github.com/owner/repo.git."
    )


def load_config(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise MirrorError(f"Config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise MirrorError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise MirrorError("config.yml must be a YAML mapping of display name to repo/config.")

    items: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for name, value in raw.items():
        if not isinstance(name, str) or not name.strip():
            raise MirrorError("Every config key in config.yml must be a non-empty string.")
        if name in seen_names:
            raise MirrorError(f"Duplicate config name: {name}")
        seen_names.add(name)

        if isinstance(value, str):
            entry: dict[str, Any] = {"repo": value}
        elif isinstance(value, dict):
            entry = dict(value)
        else:
            raise MirrorError(f"Entry '{name}' must be a repository string or a mapping.")

        if not isinstance(entry.get("repo"), str) or not entry["repo"].strip():
            raise MirrorError(f"Entry '{name}' must contain a non-empty 'repo' string.")
        repo = github_repo(entry["repo"])

        arch = entry.get("arch")
        if arch is not None:
            if not isinstance(arch, list) or any(
                not isinstance(x, str) or not x or x == "!" for x in arch
            ):
                raise MirrorError(f"Entry '{name}': 'arch' must be a list of non-empty substring filters (e.g. '!universal').")
        build = entry.get("build", False)
        if not isinstance(build, bool):
            raise MirrorError(f"Entry '{name}': 'build' must be a boolean.")

        # 'build' is intentionally accepted but currently ignored; this workflow only mirrors release APKs.
        items.append({"name": name.strip(), "repo": repo, "arch": arch, "build": build})

    return items


def make_session(token: str) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=0.6,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.headers.update({
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    })
    return session


def api_request(
    session: requests.Session,
    method: str,
    path: str,
    *,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Any:
    url = path if path.startswith("https://") else f"{API_ROOT}{path}"
    response = session.request(method, url, timeout=(20, 90), **kwargs)
    if response.status_code not in expected:
        preview = response.text[:800].replace("\n", " ")
        raise MirrorError(f"GitHub API {method} {url} returned {response.status_code}: {preview}")
    if response.status_code == 204 or not response.content:
        return None
    return response.json()


def get_latest_release(session: requests.Session, repo: str) -> dict[str, Any] | None:
    # Prefer GitHub's designated latest stable release. If a repo has no stable release
    # (e.g. a nightly-only project), fall back to its newest non-draft release, including prereleases.
    path = f"/repos/{repo}/releases/latest"
    response = session.get(f"{API_ROOT}{path}", timeout=(20, 90))
    if response.status_code == 200:
        data = response.json()
        if not data.get("draft"):
            return data
    elif response.status_code not in (404, 422):
        preview = response.text[:800].replace("\n", " ")
        raise MirrorError(f"Failed to query latest release for {repo}: {response.status_code}: {preview}")

    releases = api_request(
        session, "GET", f"/repos/{repo}/releases?per_page=20",
        expected=(200,),
    )
    published = [r for r in releases if not r.get("draft") and r.get("published_at")]
    return published[0] if published else None


def matches_arch(filename: str, filters: list[str] | None) -> bool:
    """Substring filter. Positive terms whitelist; negative terms always exclude.

    No filters => include all. Negative-only filters => include everything not excluded,
    so ["!universal"] means all APKs except universal APKs.
    """
    if not filters:
        return True
    lower_name = filename.lower()
    positives = [p.lower() for p in filters if not p.startswith("!")]
    negatives = [p[1:].lower() for p in filters if p.startswith("!")]
    if any(term in lower_name for term in negatives):
        return False
    if positives:
        return any(term in lower_name for term in positives)
    return True


def architecture_name(filename: str) -> str:
    name = filename.lower().replace("-", "_")
    if "arm64_v8a" in name or "arm64" in name or "aarch64" in name:
        return "arm64-v8a"
    if "armeabi_v7a" in name or "armv7" in name or "arm32" in name:
        return "armeabi-v7a"
    if "x86_64" in name or "x64" in name:
        return "x86_64"
    if re.search(r"(^|[_-])x86([_.-]|$)", filename.lower()):
        return "x86"
    if "universal" in name:
        return "universal"
    return "universal"


def release_version(release: dict[str, Any], display_name: str | None = None) -> str:
    """Human-facing source version/title, with a duplicated app-name prefix removed."""
    value = (release.get("name") or release.get("tag_name") or "unknown").strip()
    if display_name and value.lower().startswith(display_name.lower()):
        value = value[len(display_name):].lstrip(" :–—-_")
    return value or (release.get("tag_name") or "unknown")


def has_release_version_in_filename(filename: str, release: dict[str, Any]) -> bool:
    """Conservatively preserve upstream filenames when they carry a source version token."""
    stem = Path(filename).stem
    norm_name = normalize_for_match(stem)
    candidates: list[str] = []
    for value in (release.get("tag_name", ""), release.get("name", "")):
        # Semver-like token, including common -beta and +build metadata.
        candidates.extend(re.findall(r"(?<![A-Za-z0-9])v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", value, flags=re.I))
        # Common nightly date versions such as 20261110.
        candidates.extend(re.findall(r"\b20\d{6}\b", value))
    for candidate in candidates:
        if len(normalize_for_match(candidate)) >= 4 and normalize_for_match(candidate) in norm_name:
            return True
    return False


def fallback_apk_name(display_name: str, version: str, original_filename: str) -> str:
    app_slug = slug(display_name.replace(":", "-").replace(" ", "-"))
    version_part = slug(version)
    version_part = re.sub(r"^v(?=\d)", "", version_part, flags=re.I)
    arch = architecture_name(original_filename)

    stem = Path(original_filename).stem
    residue = stem.lower()
    # Remove the app name in either colon or dash forms, release version fragments, and architecture tokens.
    for candidate in sorted({display_name.lower(), display_name.lower().replace(":", "-"), display_name.lower().replace(":", "")}, key=len, reverse=True):
        residue = residue.replace(candidate, "-")
    residue = re.sub(r"v?\d+(?:[._-]\d+){1,3}(?:[-+][a-z0-9._-]+)?", "-", residue)
    for token in ("arm64-v8a", "arm64_v8a", "arm64", "aarch64", "armeabi-v7a", "armeabi_v7a", "armv7", "arm32", "x86_64", "x64", "x86", "universal"):
        residue = residue.replace(token, "-")
    residue = re.sub(r"[^a-z0-9]+", "-", residue).strip("-")
    ignored = {"apk", "release", "github"}
    residue_parts = [p for p in residue.split("-") if p and p not in ignored and p not in {"v"}]
    variant = "-".join(residue_parts[:5])

    base = f"{app_slug}-v{version_part}-{arch}"
    if variant:
        base += f"-{variant}"
    return f"{base}.apk"


def output_filename(display_name: str, asset_name: str, release: dict[str, Any], used: set[str]) -> str:
    if asset_name.lower().endswith(APK_SUFFIX) and has_release_version_in_filename(asset_name, release):
        candidate = Path(asset_name).name
    else:
        candidate = fallback_apk_name(display_name, release_version(release, display_name), asset_name)

    if candidate.lower() in used:
        p = Path(candidate)
        digest = hashlib.sha256(asset_name.encode("utf-8")).hexdigest()[:8]
        candidate = f"{p.stem}-{digest}{p.suffix}"
    used.add(candidate.lower())
    return candidate


def source_release_body(release: dict[str, Any]) -> str:
    original_title = release.get("name") or release.get("tag_name") or "Untitled release"
    original_url = release.get("html_url") or ""
    changelog = release.get("body") or ""
    # Keep the changelog text intact after the separator.
    return f"# {original_title}\n\n[원본 릴리스]({original_url})\n\n---\n\n{changelog}"


def target_tag(repo: str, release: dict[str, Any]) -> str:
    repo_part = slug(repo.replace("/", "-"))
    tag = release.get("tag_name") or release.get("name") or "release"
    tag_part = slug(tag)[:70]
    digest = hashlib.sha256(f"{repo}@{tag}".encode("utf-8")).hexdigest()[:10]
    return f"termux-mirror-{repo_part}-{tag_part}-{digest}"[:240]


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def select_apk_assets(release: dict[str, Any], filters: list[str] | None) -> list[dict[str, Any]]:
    assets = [a for a in release.get("assets", []) if str(a.get("name", "")).lower().endswith(APK_SUFFIX)]
    return [a for a in assets if matches_arch(str(a.get("name", "")), filters)]


def expected_names(display_name: str, release: dict[str, Any], assets: list[dict[str, Any]]) -> list[str]:
    used: set[str] = set()
    return [output_filename(display_name, str(asset["name"]), release, used) for asset in assets]


def get_target_release(session: requests.Session, target_repo: str, tag: str) -> dict[str, Any] | None:
    path = f"/repos/{target_repo}/releases/tags/{quote(tag, safe='')}"
    response = session.get(f"{API_ROOT}{path}", timeout=(20, 90))
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        preview = response.text[:800].replace("\n", " ")
        raise MirrorError(f"Failed to read target release {tag}: {response.status_code}: {preview}")
    return response.json()


def download_asset(asset: dict[str, Any], destination: Path) -> None:
    url = asset.get("browser_download_url")
    if not isinstance(url, str) or urlparse(url).scheme != "https":
        raise MirrorError(f"Invalid HTTPS asset URL for {asset.get('name')}")
    # Deliberately do not forward the repository token to an asset URL.
    with requests.get(url, stream=True, timeout=(30, 180), headers={"User-Agent": USER_AGENT}) as response:
        response.raise_for_status()
        with destination.open("wb") as out:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    out.write(chunk)
    if not destination.exists() or destination.stat().st_size == 0:
        raise MirrorError(f"Downloaded empty asset: {asset.get('name')}")


def resign_apk(source: Path, destination: Path) -> None:
    keystore = os.environ.get("SIGNING_KEYSTORE")
    store_password = os.environ.get("SIGNING_STORE_PASSWORD")
    key_alias = os.environ.get("SIGNING_KEY_ALIAS")
    key_password = os.environ.get("SIGNING_KEY_PASSWORD")
    if not all((keystore, store_password, key_alias, key_password)):
        raise MirrorError(
            "Signing secrets are missing. Configure SIGNING_KEYSTORE, SIGNING_STORE_PASSWORD, "
            "SIGNING_KEY_ALIAS and SIGNING_KEY_PASSWORD."
        )
    apksigner = shutil.which("apksigner")
    if not apksigner:
        android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if android_home:
            candidates = sorted(Path(android_home, "build-tools").glob("*/apksigner"), reverse=True)
            apksigner = str(candidates[0]) if candidates else None
    if not apksigner:
        raise MirrorError("apksigner not found on PATH or in Android SDK build-tools.")

    # Use environment variables for passwords so they do not appear in process arguments.
    env = os.environ.copy()
    env["KS_PASS_TEMP"] = store_password
    env["KEY_PASS_TEMP"] = key_password
    cmd = [
        apksigner, "sign",
        "--ks", str(keystore),
        "--ks-key-alias", key_alias,
        "--ks-pass", "env:KS_PASS_TEMP",
        "--key-pass", "env:KEY_PASS_TEMP",
        "--out", str(destination),
        str(source),
    ]
    result = subprocess.run(cmd, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        raise MirrorError(f"apksigner failed for {source.name}: {result.stderr[-2000:]}")
    verify = subprocess.run([apksigner, "verify", "--verbose", str(destination)], text=True, capture_output=True)
    if verify.returncode != 0:
        raise MirrorError(f"apksigner verification failed for {destination.name}: {verify.stderr[-2000:]}")


def upload_asset(session: requests.Session, release: dict[str, Any], file_path: Path, name: str) -> None:
    url = (release.get("upload_url") or "").split("{", 1)[0]
    if not url:
        raise MirrorError(f"Release {release.get('tag_name')} has no upload URL")
    full_url = f"{url}?name={quote(name, safe='')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": session.headers["Authorization"],
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/vnd.android.package-archive",
        "User-Agent": USER_AGENT,
    }
    with file_path.open("rb") as stream:
        response = requests.post(full_url, headers=headers, data=stream, timeout=(30, 300))
    if response.status_code not in (201,):
        raise MirrorError(f"Upload of {name} failed ({response.status_code}): {response.text[:1000]}")


def delete_release_assets(session: requests.Session, target_repo: str, release: dict[str, Any]) -> None:
    for asset in release.get("assets", []):
        api_request(
            session, "DELETE", f"/repos/{target_repo}/releases/assets/{asset['id']}",
            expected=(204,),
        )


def create_or_update_release(
    session: requests.Session,
    target_repo: str,
    tag: str,
    display_title: str,
    body: str,
    source_release: dict[str, Any],
    existing: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = {
        "tag_name": tag,
        "name": display_title,
        "body": body,
        "draft": False,
        "prerelease": bool(source_release.get("prerelease", False)),
        "make_latest": "true" if not source_release.get("prerelease", False) else "false",
    }
    if existing is None:
        # GitHub creates the tag at the default branch HEAD if tag_name does not exist.
        return api_request(session, "POST", f"/repos/{target_repo}/releases", json=payload, expected=(201,))
    return api_request(
        session, "PATCH", f"/repos/{target_repo}/releases/{existing['id']}",
        json={k: v for k, v in payload.items() if k != "tag_name"}, expected=(200,),
    )


def inspect_one(session: requests.Session, target_repo: str, item: dict[str, Any]) -> dict[str, Any] | None:
    """Read release metadata and decide whether a mirror operation is needed."""
    display_name = item["name"]
    repo = item["repo"]
    source = get_latest_release(session, repo)
    if source is None:
        print(f"{display_name}: no published release; skipped.")
        return None

    assets = select_apk_assets(source, item.get("arch"))
    if not assets:
        print(f"{display_name}: no APK assets match the configured filter; skipped.")
        return None

    names = expected_names(display_name, source, assets)
    tag = target_tag(repo, source)
    existing = get_target_release(session, target_repo, tag)
    source_updated = parse_datetime(source.get("updated_at"))
    target_updated = parse_datetime((existing or {}).get("updated_at"))
    existing_names = sorted(a.get("name", "").lower() for a in (existing or {}).get("assets", []))
    expected_lower = sorted(n.lower() for n in names)
    unchanged = (
        existing is not None
        and source_updated is not None
        and target_updated is not None
        and source_updated <= target_updated
        and existing_names == expected_lower
    )
    return {
        "display_name": display_name,
        "repo": repo,
        "source": source,
        "assets": assets,
        "names": names,
        "tag": tag,
        "existing": existing,
        "unchanged": unchanged,
    }


def mirror_one(session: requests.Session, target_repo: str, item: dict[str, Any]) -> str:
    print(f"\n== {item['name']} ({item['repo']}) ==", flush=True)
    plan = inspect_one(session, target_repo, item)
    if plan is None:
        return "skip"
    if plan["unchanged"]:
        print(f"No upstream update since mirror release was published ({plan['source'].get('tag_name')}); skipped.")
        return "unchanged"

    display_name = plan["display_name"]
    repo = plan["repo"]
    source = plan["source"]
    assets = plan["assets"]
    names = plan["names"]
    tag = plan["tag"]
    existing = plan["existing"]

    title = f"{display_name} {release_version(source, display_name)}".strip()
    body = source_release_body(source)
    print(f"Source release: {source.get('html_url')} ({source.get('updated_at')})")
    print(f"Selected {len(assets)} APK(s): {', '.join(names)}")

    with tempfile.TemporaryDirectory(prefix="termux-mirror-") as tmp:
        temp = Path(tmp)
        signed_files: list[tuple[Path, str]] = []
        used_names: set[str] = set()
        for asset in assets:
            original = str(asset["name"])
            output_name = output_filename(display_name, original, source, used_names)
            downloaded = temp / f"download-{len(signed_files)}.apk"
            signed = temp / output_name
            print(f"Downloading and signing: {original} -> {output_name}", flush=True)
            download_asset(asset, downloaded)
            resign_apk(downloaded, signed)
            signed_files.append((signed, output_name))

        # Update the release metadata successfully before removing old assets. If the API update
        # fails, the prior release assets remain available; an interrupted upload is repaired next run.
        target_release = create_or_update_release(session, target_repo, tag, title, body, source, existing)
        if existing is not None:
            delete_release_assets(session, target_repo, existing)
        for file_path, output_name in signed_files:
            upload_asset(session, target_release, file_path, output_name)
            print(f"Uploaded: {output_name}", flush=True)

    print(f"Published: https://github.com/{target_repo}/releases/tag/{tag}")
    return "published" if existing is None else "updated"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="addons.yml", type=Path)
    parser.add_argument("--check-only", action="store_true", help="Only check whether any upstream release needs mirroring")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    target_repo = os.environ.get("TARGET_REPOSITORY")
    if not token:
        print("Missing GITHUB_TOKEN environment variable.", file=sys.stderr)
        return 2
    if not target_repo or "/" not in target_repo:
        print("Missing or invalid TARGET_REPOSITORY environment variable.", file=sys.stderr)
        return 2
    if not args.check_only and not os.environ.get("SIGNING_KEYSTORE"):
        print("Missing SIGNING_KEYSTORE environment variable.", file=sys.stderr)
        return 2

    try:
        items = load_config(args.config)
        session = make_session(token)
        if args.check_only:
            needs_update = False
            errors = 0
            for item in items:
                try:
                    print(f"Checking {item['name']} ({item['repo']})", flush=True)
                    plan = inspect_one(session, target_repo, item)
                    if plan is not None and not plan["unchanged"]:
                        needs_update = True
                        print(f"Update needed: {item['name']} ({plan['source'].get('tag_name')})")
                except Exception as exc:
                    errors += 1
                    print(f"ERROR: {item['name']} ({item['repo']}): {exc}", file=sys.stderr, flush=True)
            output_path = os.environ.get("GITHUB_OUTPUT")
            if output_path:
                with open(output_path, "a", encoding="utf-8") as output:
                    output.write(f"needs_update={'true' if needs_update else 'false'}\n")
            print(f"needs_update={'true' if needs_update else 'false'}")
            return 1 if errors else 0

        counts = {"published": 0, "updated": 0, "unchanged": 0, "skip": 0, "error": 0}
        for item in items:
            try:
                status = mirror_one(session, target_repo, item)
                counts[status] = counts.get(status, 0) + 1
            except Exception as exc:
                counts["error"] += 1
                print(f"ERROR: {item['name']} ({item['repo']}): {exc}", file=sys.stderr, flush=True)
        print("\nSummary: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
        return 1 if counts["error"] else 0
    except MirrorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
