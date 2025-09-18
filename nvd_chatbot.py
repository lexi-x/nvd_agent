import os
import requests
import traceback
from langchain.tools import tool
from langchain_groq import ChatGroq
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

# Simple direct approach - no agents, just manual tool calling
@tool
def nvd_tool(keyword, pub_start_date, pub_end_date, severity) -> str:
    """Search the National Vulnerability Database (NVD) for known vulnerabilities.
    
    Args:
        keyword: search term - can be CVE ID, software name, or vulnerability type
        pub_start_date: Optional start date in YYYY-MM-DD format (pass null if not needed)
        pub_end_date: Optional end date in YYYY-MM-DD format (pass null if not needed)
        severity: Optional severity filter (LOW, MEDIUM, HIGH, CRITICAL) (pass null if not needed)
    
    Returns formatted vulnerability information.
    """
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    if keyword.upper().startswith("CVE-"):
        params = {"cveId": keyword, "resultsPerPage": 5}
    else:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
    
    if pub_start_date:
        params["pubStartDate"] = pub_start_date + "T00:00:00.000"
    if pub_end_date:
        params["pubEndDate"] = pub_end_date + "T23:59:59.000"
    if severity:
        params["cvssV3Severity"] = severity.upper()

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"No vulnerabilities found for: {keyword}"
        
        results = []
        for item in vulns:
            cve = item.get("cve", {})
            identifier = cve.get("id", "unknown")
            published_date = cve.get("published", "unknown")
            cna = cve.get("cna", {}).get("title", "unknown")
            descriptions = cve.get("descriptions", [])
            if descriptions:
                description = descriptions[0].get("value", "No description")[:200]
        results.append({
            "Identifier": identifier,
            "Published_Date": published_date,
            "CNA": cna,
            "Description": description
        })

        return results
        
    except Exception as e:
        return f"Error: {e}"

def main():
    
    print("NVD Security Assistant (Type exit or quit to terminate)")
    
    llm = ChatGroq(
        model="deepseek-r1-distill-llama-70b", 
        temperature=0, 
        api_key=os.getenv("GROQ_API_KEY")
    )
    
    tools = [nvd_tool]
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", 
         "You are a cybersecurity assistant with access to the National Vulnerability Database (NVD). "
         "When users ask about vulnerabilities, CVEs, or security issues, use the nvd_tool to get current information. "
         "Always use the tool to get up-to-date vulnerability data rather than relying on your training data. "
         "Provide clear, helpful explanations of the vulnerability details."
        ),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad")
    ])
        
    try:
        agent = create_tool_calling_agent(llm, tools, prompt)
    except Exception as e:
        print(f"Agent calling failed: {e}")
    
    agent_executor = AgentExecutor(
        agent=agent, 
        tools=tools, 
        verbose=True,
        handle_parsing_errors=True
    )
    
    while True:
        query = input("> ")
        if query.strip().lower() in {"exit", "quit", "q"}:
            break
            
        try:
            result = agent_executor.invoke({"input": query})
            print(f"\n {result['output']}\n")
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

if __name__ == "__main__":
    main()