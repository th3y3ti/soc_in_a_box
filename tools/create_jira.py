import os
from dotenv import load_dotenv
from jira import JIRA

# Load environment variables
load_dotenv()

# Get Jira credentials from environment variables
jira_url = os.getenv('JIRA_BASE_URL').rstrip('/')  # Remove trailing slash if present
jira_token = os.getenv('JIRA_API_KEY')
jira_email = os.getenv('JIRA_EMAIL')

print(f"Using Jira URL: {jira_url}")
print(f"Using email: {jira_email}")
print("Token loaded successfully")

try:
    # Connect to Jira using basic auth with email and token
    jira = JIRA(
        server=jira_url,
        basic_auth=(jira_email, jira_token)
    )
    print("Successfully connected to Jira")

    # Create a new issue
    issue_dict = {
        'project': 'SOC',  # Replace with your project key
        'summary': 'Hello World',
        'description': 'This is a test issue created from Python',
        'issuetype': {'name': 'Task'},
    }

    new_issue = jira.create_issue(fields=issue_dict)
    print(f'Created issue: {new_issue.key}')
except Exception as e:
    print(f"Error occurred: {str(e)}")
    print("\nTroubleshooting tips:")
    print("1. Verify your Jira URL is correct")
    print("2. Check if your API token is valid")
    print("3. Ensure your email address is correct")
    print("4. Verify you have access to the project 'SOC'") 