import os
from dotenv import load_dotenv
from agents.metasploit_agent import MetasploitModuleAgent
from agents.jira_agent import JiraAgent

def main():
    """Main entry point for the SOC in a Box application"""
    # Load environment variables
    load_dotenv()
    
    print("SOC in a Box - Security Operations Center Automation")
    print("===================================================")
    
    # Initialize agents
    metasploit_agent = MetasploitModuleAgent()
    jira_agent = JiraAgent()
    
    print("\nChecking for new Metasploit modules...")
    
    # Process new modules
    results = metasploit_agent.process_new_modules()
    
    if results:
        print(f"\nFound {len(results)} new modules to process")
        
        # Create Jira tickets for each new module
        for module_data in results:
            print(f"\nProcessing module: {module_data['module_name']}")
            
            # Create Jira ticket
            issue_key = jira_agent.create_ticket(module_data)
            if issue_key:
                print(f"Created Jira ticket: {issue_key}")
            else:
                print("Failed to create Jira ticket")
                
        print("\nProcessing complete!")
    else:
        print("\nNo new modules found.")
    
    print("\nApplication completed successfully.")

if __name__ == "__main__":
    main() 