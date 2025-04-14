# soc-in-a-box

An AI-powered platform designed to revolutionize Security Operations Center (SOC) workflows through intelligent automation of detection engineering, alert triage, investigation support, knowledge management, proactive hunting, controls validation, and compliance mapping.

*Note: This is a personal project focused on learning and developing Generative AI skills, applying approaches and techniques refined over two decades of building and leading risk management and cybersecurity operations teams. It also serves as a way to contribute to the community by sharing practical tools and approaches to help build skills and advance the shared cybersecurity mission.*

## The Problem

Modern SOC teams are grappling with an increasingly complex threat landscape and operational friction:

* **Threat Intelligence Overload:** Manually tracking OSINT for emerging threats and translating them into robust detections remains a slow, reactive process.
* **Alert Fatigue & Slow Triage:** High alert volumes obscure critical threats, while manual triage and enrichment consume excessive analyst time, delaying response.
* **Cognitive Load & Interpretation:** Understanding the context and implications of complex alerts and chains of events quickly during triage and investigation is challenging.
* **Knowledge Silos & Repetitive Work:** Valuable insights from investigations are often lost, leading to inconsistent analysis and repeated efforts.
* **Validation Gaps:** Ensuring that security controls are actually implemented correctly and remain effective against specific threats is often difficult and performed infrequently.
* **Operational Disconnect:** Mapping daily security operations to compliance requirements and demonstrating control effectiveness is frequently a manual, periodic burden.

## Our Solution: soc-in-a-box

`soc-in-a-box` addresses these challenges by deploying a suite of specialized AI agents that collaborate to create a proactive, intelligent, and continuously improving security operations ecosystem:

* **AI-Driven Detection Pipeline:** Monitors OSINT, prioritizes relevant threats, and generates actionable detection engineering tasks.
* **AI-Powered Triage & Investigation Support:** Integrates with your XDR (*Note: Flexibility for Wazuh, Open XDR, etc.*), automatically triages alerts, enriches them with context, **explains alerts and event sequences in plain language** to accelerate understanding, suggests response actions, and initiates investigation workflows. Includes analyst feedback loops for continuous improvement.
* **AI Knowledge Management & Contextualization:** Builds and maintains a dynamic knowledge base from past investigations, mapped to MITRE ATT&CK, providing deep context for new incidents and preserving institutional memory.
* **AI-Assisted Proactive Security:** Suggests and helps execute threat hunting playbooks based on intelligence and internal data, and facilitates continuous validation and auditing of security controls against known threats and frameworks.
* **Integrated Compliance Mapping:** Leverages operational data to provide ongoing insights and evidence related to policy and control framework mappings (e.g., NIST CSF, CIS Controls, ISO 27001).

## Key Features

**Detection Engineering Augmentation:**

* Configurable OSINT Monitoring (Blogs, Feeds, Social Media etc.)
* AI-Powered Detection Idea Prioritization
* Automated Detection Engineering Task/Ticket Creation

**Intelligent Alert Processing & Investigation Support:**

* Flexible XDR Integration (Planned: Wazuh, Open XDR)
* AI-Powered Alert Triage & Prioritization
* Automated Contextual Enrichment (Threat Intel, Assets, User Behavior)
* AI Explanation of Alerts & Events (Plain Language Summaries)
* Response Playbook / Action Suggestions
* Analyst Feedback Loop for Triage Tuning
* Automated Investigation Creation & Handover

**Knowledge Management & Strategic Insight:**

* AI-Maintained Investigation Knowledge Base
* Automated MITRE ATT&CK Mapping (KB & Alerts)
* Policy & Control Framework Mapping Capabilities (e.g., NIST CSF, CIS)

**Proactive Security & Validation:**

* AI-Suggested Threat Hunting Playbooks & Support
* Security Controls Validation & Auditing Assistance

**Visibility & Workflow:**

* Operational Dashboard for Monitoring AI Agents & Key Metrics
* ChatOps Integration (e.g., Slack, Teams) for Notifications

## Vision

Our vision for `soc-in-a-box` is to create an indispensable AI partner that transforms security operations from a reactive posture to a proactive, intelligence-driven state. By automating repetitive tasks, providing deep contextual understanding, preserving knowledge, enabling proactive threat hunting, facilitating continuous controls validation, and bridging the gap to compliance, `soc-in-a-box` empowers analysts to focus their expertise on the most critical threats and strategic initiatives. It aims to be a truly adaptive "SOC-in-a-box" that significantly enhances the efficiency, effectiveness, and resilience of security teams.

## Current Modules

### Metasploit Module Monitor (MMM)

Located in `src/mmm/`, this module monitors the Metasploit Framework repository for new or modified modules in the `auxiliary`, `exploits`, and `post` directories.

### Jira Integration

Located in the root directory, this module provides functionality for creating and managing Jira issues.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/th3y3ti/soc_in_a_box.git](https://github.com/th3y3ti/soc_in_a_box.git)
    cd soc_in_a_box
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    # On Windows
    .venv\Scripts\activate
    # On macOS/Linux
    source .venv/bin/activate
    ```

3.  **Install required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Create a `.env` file** in the root directory with your credentials:
    ```env
    GITHUB_TOKEN=your_github_token_here
    JIRA_API_KEY=your_jira_api_key
    JIRA_BASE_URL=[https://your-domain.atlassian.net](https://your-domain.atlassian.net) # Example
    JIRA_EMAIL=your_email@example.com
    ```

## Contributing

We welcome contributions! Please see our `Contributing Guidelines` (link needed if available) for details.

## License

MIT License