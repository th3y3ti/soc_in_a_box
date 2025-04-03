import os
from dotenv import load_dotenv
from tools.create_jira import create_jira_issue
from tools.metasploit_module_monitor import get_recent_modules

def main():
    """Main entry point for the SOC in a Box application"""
    # Load environment variables
    load_dotenv()
    
    print("SOC in a Box - Security Operations Center Automation")
    print("===================================================")
    
    # TODO: Add main application logic here
    # This could include:
    # - Monitoring for new Metasploit modules
    # - Creating Jira issues for new findings
    # - Running security scans
    # - Processing alerts
    
    print("\nApplication initialized successfully.")

if __name__ == "__main__":
    main() 