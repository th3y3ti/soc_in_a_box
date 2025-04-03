import os
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_github_token():
    """Get GitHub token from environment variables"""
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        raise ValueError("GitHub token not found in environment variables. Please add GITHUB_TOKEN to your .env file")
    return token

def get_recent_modules():
    """Get modules added in the last 24 hours from the Metasploit modules directories"""
    token = get_github_token()
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    try:
        # Get the current time and 24 hours ago
        now = datetime.utcnow()
        yesterday = now - timedelta(days=5)
        
        # Get all commits in the last 24 hours
        commits_url = "https://api.github.com/repos/rapid7/metasploit-framework/commits"
        params = {
            'since': yesterday.isoformat()
        }
        
        commits_response = requests.get(commits_url, headers=headers, params=params)
        commits_response.raise_for_status()
        commits = commits_response.json()
        
        # Use a dictionary to store the most recent version of each file
        recent_modules = {}
        target_dirs = ['modules/auxiliary', 'modules/exploits', 'modules/post']
        
        # Process each commit
        for commit in commits:
            # Get the files changed in this commit
            commit_sha = commit['sha']
            commit_url = f"https://api.github.com/repos/rapid7/metasploit-framework/commits/{commit_sha}"
            commit_response = requests.get(commit_url, headers=headers)
            commit_response.raise_for_status()
            commit_details = commit_response.json()
            
            # Check each file in the commit
            for file in commit_details['files']:
                if (any(file['filename'].startswith(target_dir) for target_dir in target_dirs) and 
                    file['filename'].endswith(('.rb', '.md'))):
                    # Only update if this is a more recent commit for this file
                    if (file['filename'] not in recent_modules or 
                        commit['commit']['author']['date'] > recent_modules[file['filename']]['last_commit']):
                        recent_modules[file['filename']] = {
                            'name': os.path.basename(file['filename']),
                            'path': file['filename'],
                            'url': file['blob_url'],
                            'last_commit': commit['commit']['author']['date'],
                            'status': file['status'],  # Added, modified, or removed
                            'type': file['filename'].split('/')[1]  # auxiliary, exploits, or post
                        }
        
        # Convert dictionary values to list
        return list(recent_modules.values())
    
    except requests.exceptions.RequestException as e:
        print(f"Error accessing GitHub API: {str(e)}")
        return []

def main():
    """Main function to check for recent modules and display results"""
    print("Checking for new Metasploit modules in auxiliary, exploits, and post directories...")
    recent_modules = get_recent_modules()
    
    if recent_modules:
        print(f"\nFound {len(recent_modules)} new or modified modules:")
        for module in recent_modules:
            print(f"\nModule: {module['name']}")
            print(f"Type: {module['type']}")
            print(f"Path: {module['path']}")
            print(f"URL: {module['url']}")
            print(f"Status: {module['status']}")
            print(f"Last modified: {module['last_commit']}")
    else:
        print("\nNo new or modified modules found in the last 24 hours.")

if __name__ == "__main__":
    main() 