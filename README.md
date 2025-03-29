# Metasploit Module Monitor

A Python script that monitors the Metasploit Framework repository for new or modified modules in the auxiliary, exploits, and post directories.

## Features

- Monitors changes in the last 24 hours
- Checks modules in auxiliary, exploits, and post directories
- Shows the most recent version of each modified file
- Displays module type, status, and last modification date
- Efficiently uses GitHub API to minimize requests

## Requirements

- Python 3.6+
- GitHub API token
- Required Python packages (see requirements.txt)

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/metasploit-module-monitor.git
cd metasploit-module-monitor
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your GitHub token:
```
GITHUB_TOKEN=your_github_token_here
```

## Usage

Run the script:
```bash
python check_metasploit_modules.py
```

## Output

The script will display:
- Module name
- Module type (auxiliary/exploits/post)
- Full path
- URL to view the file
- Status (added/modified/removed)
- Last modification date

## License

MIT License
