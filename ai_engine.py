import os
import asyncio
from common import event_manager

class AIEngine:
    def __init__(self, api_key: str):
        if not api_key or not isinstance(api_key, str) or len(api_key.strip()) < 10:
            raise ValueError("Invalid API key provided")
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
        except ImportError:
            raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize AI model: {e}")

    async def generate_executive_summary(self, findings: list) -> str:
        if not findings:
            return "No vulnerabilities found during the scan."
        
        prompt = self._build_prompt(findings)
        
        try:
            response = await asyncio.get_running_loop().run_in_executor(
                None, 
                lambda: self.model.generate_content(prompt)
            )
            
            if response and hasattr(response, 'text') and response.text:
                return response.text
            else:
                return "AI analysis completed but no summary was generated."
                
        except Exception as e:
            error_msg = f"AI analysis failed: {str(e)}"
            await event_manager.emit("log", f"[AI] {error_msg}")
            return error_msg

    def _build_prompt(self, findings: list) -> str:
        vuln_summary = {}
        for finding in findings:
            try:
                severity = finding.get('severity', 'P4') if isinstance(finding, dict) else 'P4'
                vuln_type = finding.get('type', 'Unknown') if isinstance(finding, dict) else 'Unknown'
                if severity not in vuln_summary:
                    vuln_summary[severity] = {}
                if vuln_type not in vuln_summary[severity]:
                    vuln_summary[severity][vuln_type] = 0
                vuln_summary[severity][vuln_type] += 1
            except Exception:
                continue

        prompt = "Generate a concise executive summary for this web application security scan. Do NOT use markdown. Use plain text with clear section headers.\n\n"
        prompt += "CRITICAL VULNERABILITIES FOUND:\n"
        
        for severity in ['P1', 'P2', 'P3', 'P4']:
            if severity in vuln_summary:
                prompt += f"\n{severity} Issues:\n"
                for vuln_type, count in vuln_summary[severity].items():
                    prompt += f"  - {vuln_type}: {count} instance(s)\n"

        prompt += "\nProvide a brief technical overview, business impact assessment, and remediation priorities. Keep under 200 words."
        return prompt