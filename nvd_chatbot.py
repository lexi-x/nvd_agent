import os
import requests
from dotenv import load_dotenv

from langchain.tools import tool
from langchain_groq import ChatGroq
from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.prompts import PromptTemplate
from langchain import hub

@tool (return_direct=True)
def nvd_tool (keyword: str, cve_id: str = None, pub_start_date: str = None, pub_end_date: str = None, severity: str = None) -> str:
    """Search the National Vulnerability Database (NVD) for known vulnerabilities using a keyword or CVE ID. 
    Inputs: 
    keyword (string describing keyword)
    cve_id (optional string for CVE if given)
    pub_start_date (optional start date to filter by)
    pub_end_date (optional end date to filter by)
    severity (optional severity filter)

    returns list of vulnerability search results as dictionaries
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    if cve_id:
        params["cveId"] = cve_id
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
    except Exception as e:
        return f"Error querying NVD: {e}"

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print("none")
        return "No vulnerabilities found."

    results = []
    for item in vulns:
        cve = item.get("cve", {})
        identifier = cve.get("id", "unknown")
        published_date = cve.get("published", "unknown")
        cna = cve.get("cna", {}).get("title", "unknown")
        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "No description provided") if descriptions else "No description provided"

        results.append({
            "Identifier": identifier,
            "Published_Date": published_date,
            "CNA": cna,
            "Description": description
        })

    if not results:
        return "Error: No valid vulnerability data could be extracted."
    
    return results

def main():
    
    print("NVD Chatbot (type 'exit' to quit)")
    
    # Initialize LLM and tools
    llm = ChatGroq(model="deepseek-r1-distill-llama-70b", temperature=0, api_key=os.getenv("GROQ_API_KEY"))
    tools = [nvd_tool]
    prompt = PromptTemplate.from_template("""Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: {input}
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: "input_type"="search_term", where input type is the most closely aligned input given
Observation: the records outputted by nvd_tool
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: {agent_scratchpad} I now have the information
Action: I will proceed to explain the specific vulnerability details
Final Answer: natural language explanation of relevant result descriptions.                      
""")

    # Create the agent and executor
    agent = create_react_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=3
    )
    
    while True:
        query = input("\n> ")
        if query.strip().lower() in {"exit", "quit"}:
            break
        try:
            response = agent_executor.invoke({"input": query})      
            print(response["output"])
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()