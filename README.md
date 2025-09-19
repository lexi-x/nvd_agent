# NVD Security Chatbot

A simple command-line chat interface that searches the National Vulnerability Database (NVD) for known software vulnerabilities and CVEs using natural language queries.

## Features
- Search NVD for vulnerabilities by keyword, CVE ID, start/end date, and/or severity
- Natural language communication

## Setup
1. Clone this repository
2. Install dependencies (see `requirements.txt`):
   ```
   pip install -r requirements.txt
   ```
3. Set your API keys as environment variables:
   - `NVD_API_KEY` 
   - `GROQ_API_KEY` (free for limited tokens)

## Usage
Run the chatbot:
```
python nvd_chatbot.py
```
Type your question after the >. Type `exit` or `quit` to stop.

## License
MIT
