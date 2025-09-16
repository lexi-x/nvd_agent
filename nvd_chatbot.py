import os
import requests
from dotenv import load_dotenv

from langchain.tools import tool
from langchain_groq import ChatGroq
from langchain.agents import initialize_agent, AgentType

@tool ("nvd_tool")
def nvd_tool (keyword: str, pub_start_date: str = None, pub_end_date: str = None, severity: str = None) -> str:
    '''Search the National Vulnerability Database (NVD) for known vulnerabilities using a keyword or CVE ID. Optionally filter by severity or date range.'''
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

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
        print(data)
    except Exception as e:
        return f"Error querying NVD: {e}"

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return "No vulnerabilities found."

    results = []
    for item in vulns:
        cve = item.get("cve", {})
        identifier = cve.get("id", "UNKNOWN")
        cisa_info = cve.get("cisaKeV", "N/A")  # only present if the KEV entry exists
        published_date = cve.get("published", "UNKNOWN")
        cna = cve.get("cna", {}).get("title", "UNKNOWN")
        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "No description provided") if descriptions else "No description provided"

        results.append({
            "Identifier": identifier,
            "CISA_KEV_Info": cisa_info,
            "Published_Date": published_date,
            "CNA": cna,
            "Description": description
        })
        # cve_id = item["cve"]["id"]
        # desc = item["cve"]["descriptions"][0]["value"]
        # severity_val = (
        #     item["cve"]
        #     .get("metrics", {})
        #     .get("cvssMetricV31", [{}])[0]
        #     .get("cvssData", {})
        #     .get("baseSeverity", "UNKNOWN")
        # )
        # results.append(f"{cve_id} ({severity_val}): {desc}")

    return results

# Initialize LLM and tools
llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0, api_key = os.getenv("GROQ_API_KEY"))
tools = [nvd_tool]

# Initialize agent
agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    agent_kwargs={
        "system_message": (
            "You are a cybersecurity assistant. "
            "When you receive vulnerability data, summarize it clearly, "
            "explain the severity, risks, and potential mitigations in plain English."
        )
    },
    verbose=True
)

def main():
    print("NVD Chatbot (type 'exit' to quit)")
    
    while True:
        query = input("\n> ")
        if query.strip().lower() in {"exit", "quit"}:
            break
        try:
            # call the tool directly
            raw_vulns = nvd_tool(query)

            # format as text
            text_output = "\n".join(f"{v['Identifier']}: {v['Description']}" for v in raw_vulns)

            # pass to LLM for explanation
            explained = agent.invoke(f"Explain these vulnerabilities in plain English, including risks and mitigation steps:\n{text_output}"
            )
            # answer = agent.invoke({"input": query})
            # print(answer)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()