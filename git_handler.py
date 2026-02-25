# git_handler.py
import os
import urllib.parse
from git import Repo, exc
import sys

def clone_repository_from_env(repo_url, temp_dir):
    """
    Clones a Git repository using configuration from environment variables.

    Args:
        repo_url (str): The URL of the repository to clone.
        temp_dir (str): The local temporary directory to clone into.

    Returns:
        bool: True if cloning was successful, False otherwise.
    """
    # Default to public if the variable is not set
    is_public = os.getenv("IS_PUBLIC_REPO", "true").lower() == 'true'

    if is_public:
        try:
            print(f"Cloning public repository {repo_url} into {temp_dir}...", flush=True)
            Repo.clone_from(repo_url, temp_dir)
            print("✅ Clone complete.", flush=True)
            return True
        except exc.GitCommandError as e:
            print(f"❌ ERROR: Failed to clone public repository. It might be private or the URL is incorrect.", flush=True)
            print(f"   Git Error: {e}", flush=True)
            return False
    else: # Private repository logic
        print("\n--- Private Repository Authentication (from .env) ---", flush=True)
        provider = os.getenv("GIT_PROVIDER")
        username = os.getenv("GIT_USERNAME")
        token = None

        if not provider or not username:
            print("❌ ERROR: For private repos, GIT_PROVIDER and GIT_USERNAME must be set in your .env file.", flush=True)
            return False

        # Get the correct token based on the provider
        if provider == "github":
            token = os.getenv("GITHUB_TOKEN")
        elif provider == "gitlab":
            token = os.getenv("GITLAB_TOKEN")
        elif provider == "bitbucket":
            token = os.getenv("BITBUCKET_APP_PASSWORD")
        
        if not token:
            print(f"❌ ERROR: Token for provider '{provider}' not found in .env file.", flush=True)
            print("   Please set GITHUB_TOKEN, GITLAB_TOKEN, or BITBUCKET_APP_PASSWORD.", flush=True)
            return False

        # Construct the authenticated clone URL
        parsed_url = urllib.parse.urlparse(repo_url)
        # Ensure the path starts with / for urllib.parse.urlunparse
        path = parsed_url.path if parsed_url.path.startswith('/') else '/' + parsed_url.path
        
        # Reconstruct the URL with credentials in the netloc part
        netloc = f"{urllib.parse.quote(username)}:{urllib.parse.quote(token)}@{parsed_url.hostname}"
        if parsed_url.port:
            netloc += f":{parsed_url.port}"
        
        clone_url_with_creds = urllib.parse.urlunparse(
            (parsed_url.scheme, netloc, path, parsed_url.params, parsed_url.query, parsed_url.fragment)
        )
        
        try:
            print(f"Attempting to clone private repository as '{username}'...", flush=True)
            Repo.clone_from(clone_url_with_creds, temp_dir)
            print("✅ Clone complete.", flush=True)
            return True
        except exc.GitCommandError as e:
            print(f"❌ ERROR: Failed to clone private repository. Please check your credentials, permissions, and repository URL.", flush=True)
            print(f"   Git Error: {e}", flush=True)
            print(f"   Attempted clone URL (credentials obfuscated): {clone_url_with_creds.replace(token, '********') if token else clone_url_with_creds}", flush=True)
            return False
