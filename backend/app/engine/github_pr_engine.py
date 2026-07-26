import base64
import httpx
from typing import Dict, Any


def apply_diff_patch(original_content: str, fix_diff: str) -> str:
    """
    Applies unified git patch diff lines (- / +) to original file content.
    Raises RuntimeError if patch application fails due to line mismatches or content drift.
    """
    if not fix_diff or not fix_diff.strip():
        raise RuntimeError("Diff application failed: Provided AI patch diff is empty.")

    lines_to_remove = []
    lines_to_add = []

    for line in fix_diff.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            lines_to_remove.append(line[1:].strip())
        elif line.startswith("+") and not line.startswith("+++"):
            lines_to_add.append(line[1:].strip())

    result_content = original_content

    # Validate that targeted lines exist in original content before applying patch
    for target in lines_to_remove:
        if target and target not in result_content:
            raise RuntimeError(
                f"Diff application failed: Target line '{target}' was not found in the remote file. "
                "The target file may have been modified since the scan was performed."
            )
        if target:
            result_content = result_content.replace(target, "\n".join(lines_to_add), 1)

    # If simple replacement didn't trigger, append additions safely
    if result_content == original_content and lines_to_add:
        result_content = original_content.rstrip() + "\n\n# Sentinel Security Patch\n" + "\n".join(lines_to_add) + "\n"

    return result_content


def create_github_fix_pr(
    github_token: str,
    repo_name: str,  # "owner/repo"
    finding_id: int,
    rule_id: str,
    file_path: str,
    fix_diff: str,
    ai_explanation: str,
) -> Dict[str, Any]:
    """
    Applies AI suggested fix diff to a new GitHub branch and opens a Pull Request on the target repository.
    """
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base_url = f"https://api.github.com/repos/{repo_name}"

    with httpx.Client(timeout=20.0, headers=headers) as client:
        # 1. Fetch Repository Default Branch
        repo_res = client.get(base_url)
        if repo_res.status_code != 200:
            raise RuntimeError(f"Failed to fetch GitHub repository '{repo_name}': {repo_res.text}")
        default_branch = repo_res.json().get("default_branch", "main")

        # 2. Get Default Branch Commit SHA
        ref_res = client.get(f"{base_url}/git/ref/heads/{default_branch}")
        if ref_res.status_code != 200:
            raise RuntimeError(f"Failed to fetch reference for branch '{default_branch}': {ref_res.text}")
        base_sha = ref_res.json()["object"]["sha"]

        # 3. Create New Branch refs/heads/sentinel/fix-{finding_id}
        new_branch = f"sentinel/fix-finding-{finding_id}"
        create_ref_res = client.post(
            f"{base_url}/git/refs",
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha}
        )
        if create_ref_res.status_code not in [201, 422]:
            raise RuntimeError(f"Failed to create GitHub branch '{new_branch}': {create_ref_res.text}")

        # 4. Fetch File Content & SHA from New Branch
        content_res = client.get(f"{base_url}/contents/{file_path}?ref={new_branch}")
        if content_res.status_code != 200:
            raise RuntimeError(f"Failed to read file '{file_path}' from repository: {content_res.text}")

        file_data = content_res.json()
        file_sha = file_data["sha"]
        raw_b64 = file_data.get("content", "")
        original_text = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")

        # 5. Apply Patch Diff Safely
        updated_text = apply_diff_patch(original_text, fix_diff)
        updated_b64 = base64.b64encode(updated_text.encode("utf-8")).decode("utf-8")

        # 6. Commit Updated File Content to New Branch
        commit_msg = f"fix(security): resolve {rule_id} via Sentinel AI remediation"
        update_res = client.put(
            f"{base_url}/contents/{file_path}",
            json={
                "message": commit_msg,
                "content": updated_b64,
                "sha": file_sha,
                "branch": new_branch,
            }
        )
        if update_res.status_code not in [200, 201]:
            raise RuntimeError(f"Failed to commit security fix to GitHub: {update_res.text}")

        # 7. Create GitHub Pull Request
        pr_body = (
            f"## Sentinel AI Security Remediation\n\n"
            f"**Rule ID:** `{rule_id}`\n"
            f"**Target File:** `{file_path}`\n\n"
            f"### Plain-English Analysis\n{ai_explanation or 'Automated AI security fix patch.'}\n\n"
            f"---\n*Opened automatically by Sentinel Application Security Platform (Finding #{finding_id}).*"
        )
        pr_res = client.post(
            f"{base_url}/pulls",
            json={
                "title": f"[Sentinel AI Fix] Resolve {rule_id} in {file_path}",
                "head": new_branch,
                "base": default_branch,
                "body": pr_body,
            }
        )
        if pr_res.status_code not in [200, 201]:
            raise RuntimeError(f"Failed to open GitHub Pull Request: {pr_res.text}")

        pr_data = pr_res.json()
        return {
            "pr_url": pr_data.get("html_url", f"https://github.com/{repo_name}/pulls"),
            "branch_name": new_branch,
            "status": "created",
        }
