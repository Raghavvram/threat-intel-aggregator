# 🦉 Threat Intelligence Aggregator

This project is a comprehensive threat intelligence aggregation platform tailored for cybersecurity use cases. It fetches and consolidates data from multiple RSS feeds, automatically extracts Indicators of Compromise (IOCs), and uses a local LLM via Ollama to generate concise summaries of threat reports.

## ✨ Features
- **Feed Aggregation**: Collects articles from multiple cybersecurity RSS feeds.
- **IOC Extraction**: Automatically parses articles for IPs, Hashes (MD5, SHA1, SHA256), URLs, Domains, and CVEs.
- **AI Summarization**: Integrates with local LLMs via Ollama to produce structured summaries (Threat, Affected Systems, Mitigation).
- **Interactive Dashboard**: A simple and intuitive web interface built with Gradio to browse, search, and analyze threat intel.
- **Modular Codebase**: Organized into logical modules for easy maintenance and extension.

## 🛠️ Setup and Installation

### Prerequisites
- Python 3.8+
- [Ollama](https://ollama.com/) installed and running.

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd threat-intel-aggregator
```

### 2. Install Python Dependencies
Create a virtual environment (recommended) and install the required packages.
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

### 3. Set Up Ollama
1.  **Install Ollama**: Follow the instructions on the official [Ollama website](https://ollama.com/).
2.  **Pull an LLM**: You need to pull a model for summarization. The default is `llama3`.
    ```bash
    ollama pull llama3
    ```
3.  **Ensure Ollama is Running**: The Ollama application or background service must be running before you start the Python application.

## 🚀 Running the Application
With your virtual environment activated and Ollama running, launch the Gradio dashboard:
```bash
python main.py
```
Open your web browser and navigate to the local URL provided (usually `http://127.0.0.1:7860`).

The application will automatically fetch feeds on startup. You can use the **"Fetch Latest Feeds"** button to refresh the data at any time.

![Dashboard Screenshot](https://raw.githubusercontent.com/Raghavvram/threat-intel-aggregator/refs/heads/main/asserts/Threat-intel-aggreator.png)

