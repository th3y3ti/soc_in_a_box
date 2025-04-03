from tools.create_jira import create_jira_issue
import google.generativeai as genai
import os

class JiraAgent:
    def __init__(self):
        """Initialize the Jira Agent"""
        # Configure the Gemini API
        genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        
    def create_ticket(self, module_data):
        """Create a Jira ticket for a new Metasploit module"""
        # Generate ticket description using Gemini
        description = self._generate_ticket_description(module_data)
        
        # Create the Jira ticket
        summary = f"New Metasploit Module: {module_data['module_name']}"
        
        ticket_data = {
            'summary': summary,
            'description': description,
            'issuetype': {'name': 'Task'},
            'priority': {'name': 'High'},
            'labels': ['metasploit', 'security', module_data['module_type']]
        }
        
        try:
            issue_key = create_jira_issue(ticket_data)
            return issue_key
        except Exception as e:
            print(f"Error creating Jira ticket: {str(e)}")
            return None
            
    def _generate_ticket_description(self, module_data):
        """Generate a detailed ticket description using Gemini"""
        prompt = f"""
        Create a detailed Jira ticket description for a new Metasploit module with the following information:
        
        Module Name: {module_data['module_name']}
        Module Type: {module_data['module_type']}
        Module URL: {module_data['module_url']}
        
        Analysis:
        {module_data['analysis']}
        
        Snort Rule:
        {module_data['snort_rule']}
        
        Please format the description with appropriate sections and markdown formatting.
        Include:
        1. Overview of the module
        2. Impact assessment
        3. Detection capabilities (Snort rule)
        4. Recommended actions
        5. References
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"Error generating ticket description: {str(e)}")
            return None 