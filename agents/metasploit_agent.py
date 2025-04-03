import os
import google.generativeai as genai
from tools.metasploit_module_monitor import get_recent_modules

class MetasploitModuleAgent:
    def __init__(self):
        """Initialize the Metasploit Module Agent"""
        # Configure the Gemini API
        genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        
    def analyze_module(self, module_content):
        """Analyze a Metasploit module using Gemini"""
        prompt = f"""
        Analyze this Metasploit module and provide:
        1. A brief summary of what the module does
        2. The potential impact of the vulnerability it exploits
        3. The type of attack (e.g., remote code execution, privilege escalation)
        4. The affected systems or software
        
        Module content:
        {module_content}
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"Error analyzing module with Gemini: {str(e)}")
            return None
            
    def generate_snort_rule(self, module_analysis):
        """Generate a Snort rule based on the module analysis"""
        prompt = f"""
        Based on this Metasploit module analysis, create a Snort rule that would detect this attack.
        The rule should be specific and include relevant signatures.
        
        Module analysis:
        {module_analysis}
        
        Please provide only the Snort rule, nothing else.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"Error generating Snort rule with Gemini: {str(e)}")
            return None
            
    def process_new_modules(self):
        """Process new Metasploit modules and return analysis results"""
        modules = get_recent_modules()
        results = []
        
        for module in modules:
            # Get module content from GitHub
            module_content = self._get_module_content(module['url'])
            if not module_content:
                continue
                
            # Analyze the module
            analysis = self.analyze_module(module_content)
            if not analysis:
                continue
                
            # Generate Snort rule
            snort_rule = self.generate_snort_rule(analysis)
            
            results.append({
                'module_name': module['name'],
                'module_type': module['type'],
                'module_url': module['url'],
                'analysis': analysis,
                'snort_rule': snort_rule
            })
            
        return results
        
    def _get_module_content(self, url):
        """Get the content of a module from GitHub"""
        try:
            import requests
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error fetching module content: {str(e)}")
            return None 