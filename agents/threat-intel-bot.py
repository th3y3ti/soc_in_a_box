import os
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from typing import List, Dict, Optional
from pydantic import BaseModel, Field, ValidationError
import google.generativeai as genai
import logging
import base64
import html

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
GITHUB_REPO = "rapid7/metasploit-framework"
TARGET_MODULE_DIRS = ['modules/auxiliary', 'modules/exploits', 'modules/post']
DAYS_TO_CHECK = 8
GEMINI_MODEL = "gemini-2.0-flash"
MAX_CONTENT_CHARS = 75000

# Confluence Configuration
CONFLUENCE_BASE_URL = "https://your-domain.atlassian.net/wiki/rest/api"
CONFLUENCE_SPACE_KEY = "SO"  # Space key where pages will be created
CONFLUENCE_FOLDER_NAME = "Daily Intel Reports"  # Folder name for organizing pages

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# --- Pydantic Data Models ---
class ModuleInfo(BaseModel):
    """Information about a Metasploit module."""
    name: str
    path: str
    url: str
    status: str
    type: str
    last_commit_date: str = Field(alias='last_commit')
    content: Optional[str] = None

class ModuleAnalysis(BaseModel):
    """AI analysis of a Metasploit module."""
    module_path: str
    summary: str
    impact: str
    attack_type: str
    affected_systems: str
    recommendations: List[str]
    potential_indicators: List[str]
    draft_snort_rule: Optional[str] = None

class AnalysisResult(BaseModel):
    """Container for module info and its analysis."""
    module_info: ModuleInfo
    analysis: Optional[ModuleAnalysis] = None
    error: Optional[str] = None

# --- GitHub API Functions ---
def get_github_token() -> Optional[str]:
    """Get GitHub token from environment variables."""
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        logger.warning("GITHUB_TOKEN environment variable not set. API rate limits will be significantly lower.")
    return token

def get_recent_modules(token: Optional[str]) -> List[ModuleInfo]:
    """Get modules added or modified recently from the Metasploit modules directories."""
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f'token {token}'

    try:
        since_time = datetime.utcnow() - timedelta(days=DAYS_TO_CHECK)
        since_iso = since_time.isoformat() + "Z"

        commits_url = f"https://api.github.com/repos/{GITHUB_REPO}/commits"
        params = {'since': since_iso}
        logger.info(f"Fetching commits since {since_iso} from {GITHUB_REPO}")

        commits_response = requests.get(commits_url, headers=headers, params=params)
        commits_response.raise_for_status()
        commits = commits_response.json()
        logger.info(f"Found {len(commits)} commits since {since_iso}.")

        recent_modules = {}
        for commit in commits:
            commit_url = commit['url']
            commit_date = commit['commit']['committer']['date']

            try:
                commit_details = requests.get(commit_url, headers=headers).json()
                for file in commit_details.get('files', []):
                    filename = file['filename']
                    if any(filename.startswith(dir) for dir in TARGET_MODULE_DIRS) and filename.endswith('.rb'):
                        recent_modules[filename] = {
                            'name': os.path.basename(filename),
                            'path': filename,
                            'url': file.get('blob_url', 'N/A'),
                            'status': file['status'],
                            'type': filename.split('/')[1],
                            'last_commit': commit_date
                        }
            except Exception as e:
                logger.warning(f"Error processing commit {commit['sha']}: {e}")
                continue

        # Filter out removed modules and validate
        active_modules = []
        for mod_data in recent_modules.values():
            if mod_data['status'] != 'removed':
                try:
                    active_modules.append(ModuleInfo(**mod_data))
                except ValidationError as e:
                    logger.warning(f"Validation error for module {mod_data['path']}: {e}")

        logger.info(f"Found {len(active_modules)} new/modified Ruby modules")
        return active_modules

    except Exception as e:
        logger.error(f"Error fetching GitHub data: {e}")
        return []

def get_module_content(module: ModuleInfo, token: Optional[str]) -> Optional[str]:
    """Fetch the raw content of a module from GitHub."""
    try:
        headers = {'Accept': 'application/vnd.github.v3.raw'}
        if token:
            headers['Authorization'] = f'token {token}'

        raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/master/{module.path}"
        response = requests.get(raw_url, headers=headers)
        response.raise_for_status()
        return response.text

    except Exception as e:
        logger.error(f"Error fetching content for {module.path}: {e}")
        return None

# --- AI Analysis Functions ---
def initialize_ai_model() -> Optional[genai.GenerativeModel]:
    """Initialize the Google Gemini AI model."""
    try:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY environment variable not found")

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(GEMINI_MODEL)
        logger.info(f"AI model initialized: {GEMINI_MODEL}")
        return model

    except Exception as e:
        logger.error(f"Failed to initialize AI model: {e}")
        return None

def analyze_module(module: ModuleInfo, model: genai.GenerativeModel) -> Optional[ModuleAnalysis]:
    """Analyze a module using the AI model."""
    if not module.content:
        logger.warning(f"No content available for {module.path}")
        return None

    try:
        prompt = f"""
        Analyze this Metasploit module and provide a structured analysis with the following information:
        
        Module Information:
        - Name: {module.name}
        - Type: {module.type}
        - Path: {module.path}
        
        Module Content:
        ```ruby
        {module.content[:MAX_CONTENT_CHARS]}
        ```
        
        Please provide:
        1. A brief summary of the module's functionality
        2. The potential impact if exploited
        3. The type of attack (e.g., RCE, privilege escalation)
        4. Affected systems or software
        5. Security recommendations
        6. Key indicators (IPs, ports, protocols, file paths)
        7. A draft Snort rule (if applicable)
        
        Format your response in a structured way that can be parsed into these sections.
        """

        response = model.generate_content(prompt)
        if not response.text:
            raise ValueError("Empty response from AI model")

        # Parse the response into sections (this is a simplified version)
        text = response.text
        sections = text.split('\n\n')
        
        return ModuleAnalysis(
            module_path=module.path,
            summary=sections[0] if len(sections) > 0 else "No summary available",
            impact=sections[1] if len(sections) > 1 else "Impact analysis not available",
            attack_type=sections[2] if len(sections) > 2 else "Attack type not specified",
            affected_systems=sections[3] if len(sections) > 3 else "Affected systems not specified",
            recommendations=sections[4].split('\n') if len(sections) > 4 else [],
            potential_indicators=sections[5].split('\n') if len(sections) > 5 else [],
            draft_snort_rule=sections[6] if len(sections) > 6 else None
        )

    except Exception as e:
        logger.error(f"Error analyzing module {module.path}: {e}")
        return None

# --- Confluence Functions ---
def get_confluence_auth() -> Optional[Dict[str, str]]:
    """Get Confluence authentication headers."""
    try:
        email = os.getenv('CONFLUENCE_USERNAME')
        api_token = os.getenv('CONFLUENCE_API_TOKEN')
        
        if not email or not api_token:
            raise ValueError("Confluence credentials not found in environment variables")

        auth_str = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        return {
            'Authorization': f'Basic {auth_str}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    except Exception as e:
        logger.error(f"Error getting Confluence auth: {e}")
        return None

def ensure_folder_exists(headers: Dict[str, str]) -> Optional[str]:
    """Ensure the target folder exists in Confluence, create if it doesn't."""
    try:
        # First try to get all pages in the space
        response = requests.get(
            f"{CONFLUENCE_BASE_URL}/content",
            headers=headers,
            params={
                'spaceKey': CONFLUENCE_SPACE_KEY,
                'title': CONFLUENCE_FOLDER_NAME,
                'type': 'page',
                'status': 'current',
                'expand': 'space'
            }
        )
        response.raise_for_status()
        
        results = response.json().get('results', [])
        if results:
            for result in results:
                if (result['title'] == CONFLUENCE_FOLDER_NAME and 
                    result['space']['key'] == CONFLUENCE_SPACE_KEY):
                    folder_id = result['id']
                    logger.info(f"Found existing folder: {CONFLUENCE_FOLDER_NAME} (ID: {folder_id}) in space {CONFLUENCE_SPACE_KEY}")
                    return folder_id
            
            logger.warning(f"Found pages with title {CONFLUENCE_FOLDER_NAME} but none in space {CONFLUENCE_SPACE_KEY}")

        # If we get here, we need to create the folder
        # Verify space exists first
        space_response = requests.get(
            f"{CONFLUENCE_BASE_URL}/space/{CONFLUENCE_SPACE_KEY}",
            headers=headers
        )
        space_response.raise_for_status()
        
        # Create new folder at root level of space
        folder_data = {
            "type": "page",
            "title": f"{CONFLUENCE_FOLDER_NAME} ({datetime.now().strftime('%Y%m%d_%H%M%S')})",  # Add timestamp to avoid conflicts
            "space": {"key": CONFLUENCE_SPACE_KEY},
            "body": {
                "storage": {
                    "value": f"""<h1>{CONFLUENCE_FOLDER_NAME}</h1>
<p>This folder contains analysis of recent Metasploit modules. Each page in this folder represents an analysis of a module that has been recently added or modified in the Metasploit Framework.</p>

<h2>Contents</h2>
<p>Each analysis page includes:</p>
<ul>
    <li>Basic module information (name, path, type)</li>
    <li>Last modification date</li>
    <li>GitHub URL for the module</li>
    <li>AI-generated analysis summary</li>
    <li>Potential impact assessment</li>
    <li>Attack type classification</li>
    <li>Affected systems/software</li>
    <li>Security recommendations</li>
    <li>Potential indicators (IPs, ports, protocols, paths)</li>
    <li>Draft Snort rules (where applicable)</li>
</ul>

<p>This folder is automatically updated by the SOC automation system.</p>""",
                    "representation": "storage"
                }
            }
        }

        response = requests.post(
            f"{CONFLUENCE_BASE_URL}/content",
            headers=headers,
            json=folder_data
        )
        response.raise_for_status()
        
        folder_id = response.json()['id']
        logger.info(f"Created new folder: {folder_data['title']} (ID: {folder_id}) in space {CONFLUENCE_SPACE_KEY}")
        return folder_id

    except Exception as e:
        logger.error(f"Error ensuring folder exists: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response status: {e.response.status_code}")
            logger.error(f"Response body: {e.response.text}")
        return None

def create_confluence_page(result: AnalysisResult, folder_id: str, headers: Dict[str, str]) -> bool:
    """Create a Confluence page for a module analysis."""
    try:
        # Generate a unique title with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        title = f"Metasploit Module Analysis: {result.module_info.name} ({timestamp})"

        # Format the content in Confluence storage format
        content = f"""
<h1>Module Information</h1>
<table>
    <tr><th>Name</th><td>{html.escape(result.module_info.name)}</td></tr>
    <tr><th>Path</th><td>{html.escape(result.module_info.path)}</td></tr>
    <tr><th>Type</th><td>{html.escape(result.module_info.type)}</td></tr>
    <tr><th>Last Modified</th><td>{html.escape(result.module_info.last_commit_date)}</td></tr>
    <tr><th>GitHub URL</th><td><a href="{html.escape(result.module_info.url)}">{html.escape(result.module_info.url)}</a></td></tr>
</table>

<h1>Analysis</h1>
<h2>Summary</h2>
<p>{html.escape(result.analysis.summary)}</p>

<h2>Impact</h2>
<p>{html.escape(result.analysis.impact)}</p>

<h2>Attack Type</h2>
<p>{html.escape(result.analysis.attack_type)}</p>

<h2>Affected Systems</h2>
<p>{html.escape(result.analysis.affected_systems)}</p>

<h2>Security Recommendations</h2>
<ul>
"""
        for rec in result.analysis.recommendations:
            content += f"<li>{html.escape(rec)}</li>\n"
        
        content += """</ul>

<h2>Potential Indicators</h2>
<ul>
"""
        for indicator in result.analysis.potential_indicators:
            content += f"<li>{html.escape(indicator)}</li>\n"
        content += "</ul>\n"

        if result.analysis.draft_snort_rule:
            content += f"""
<h2>Draft Snort Rule</h2>
<ac:structured-macro ac:name="code">
<ac:parameter ac:name="language">text</ac:parameter>
<ac:plain-text-body><![CDATA[{result.analysis.draft_snort_rule}]]></ac:plain-text-body>
</ac:structured-macro>
"""

        # Create the page
        page_data = {
            "type": "page",
            "title": title,
            "space": {"key": CONFLUENCE_SPACE_KEY},
            "body": {
                "storage": {
                    "value": content,
                    "representation": "storage"
                }
            }
        }

        # Only add ancestor if folder_id is provided and valid
        if folder_id:
            page_data["ancestors"] = [{"id": folder_id}]

        response = requests.post(
            f"{CONFLUENCE_BASE_URL}/content",
            headers=headers,
            json=page_data
        )
        response.raise_for_status()
        
        logger.info(f"Created Confluence page: {title}")
        return True

    except Exception as e:
        logger.error(f"Error creating Confluence page for {result.module_info.name}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response status: {e.response.status_code}")
            logger.error(f"Response body: {e.response.text}")
        return False

def main():
    """Main execution function."""
    # Initialize AI model
    model = initialize_ai_model()
    if not model:
        logger.error("Failed to initialize AI model. Exiting.")
        return

    # Get GitHub token
    github_token = get_github_token()

    # Get Confluence auth headers
    confluence_headers = get_confluence_auth()
    if not confluence_headers:
        logger.error("Failed to get Confluence authentication. Exiting.")
        return

    # Ensure the target folder exists
    folder_id = ensure_folder_exists(confluence_headers)
    if not folder_id:
        logger.error("Failed to ensure target folder exists. Exiting.")
        return

    # Get recent modules
    modules = get_recent_modules(github_token)
    if not modules:
        logger.info("No new or modified modules found.")
        return

    # Process each module
    for module in modules:
        try:
            # Get module content
            content = get_module_content(module, github_token)
            if not content:
                continue
            module.content = content

            # Analyze module
            analysis = analyze_module(module, model)
            if not analysis:
                continue

            # Create result and Confluence page
            result = AnalysisResult(module_info=module, analysis=analysis)
            if create_confluence_page(result, folder_id, confluence_headers):
                logger.info(f"Successfully processed module: {module.name}")
            else:
                logger.error(f"Failed to create Confluence page for module: {module.name}")

        except Exception as e:
            logger.error(f"Error processing module {module.name}: {e}")
            continue

if __name__ == "__main__":
    main() 