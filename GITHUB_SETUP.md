# GitHub Setup Guide

This guide will help you upload this project to GitHub.

## Initial Setup

### 1. Create a GitHub Repository

1. Go to [GitHub](https://github.com) and sign in
2. Click the "+" icon in the top right
3. Select "New repository"
4. Name it (e.g., "red-team-blue-team-cybersecurity")
5. Choose **Public** or **Private** (your choice)
6. **DO NOT** initialize with README, .gitignore, or license (we already have these)
7. Click "Create repository"

### 2. Initialize Git in Your Project

```bash
cd /home/hovip1285/Downloads/gg

# Initialize git repository
git init

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: Red Team vs Blue Team cybersecurity project"
```

### 3. Connect to GitHub

```bash
# Add your GitHub repository as remote
# Replace USERNAME and REPO_NAME with your actual values
git remote add origin https://github.com/USERNAME/REPO_NAME.git

# Rename branch to main (if needed)
git branch -M main

# Push to GitHub
git push -u origin main
```

## Team Collaboration

### Option 1: Shared Repository (Recommended for Learning)

Both students work on the same repository:

1. One student creates the repository
2. Add the other student as a collaborator:
   - Go to repository Settings → Collaborators
   - Add the other student's GitHub username
3. Both students clone the repository:
   ```bash
   git clone https://github.com/USERNAME/REPO_NAME.git
   ```

### Option 2: Fork and Pull Requests

Each student works on their own fork:

1. Student 1 creates the main repository
2. Student 2 forks the repository
3. Both make changes in their own forks
4. Create Pull Requests to merge changes

## Workflow

### Daily Workflow

```bash
# Pull latest changes
git pull origin main

# Make your changes in red_team/ or blue_team/

# Check what changed
git status

# Add your changes
git add red_team/your_file.py  # or blue_team/your_file.py

# Commit with descriptive message
git commit -m "Red Team: Add new vulnerability scanner feature"

# Push to GitHub
git push origin main
```

### Branch Strategy (Optional)

For larger features, use branches:

```bash
# Create a feature branch
git checkout -b red-team/port-scanner-improvements

# Make changes and commit
git add .
git commit -m "Improve port scanner with service detection"

# Push branch
git push origin red-team/port-scanner-improvements

# Create Pull Request on GitHub to merge into main
```

## File Organization

- **Red Team student**: Work in `red_team/` directory
- **Blue Team student**: Work in `blue_team/` directory
- **Shared code**: Work in `shared/` directory
- **Documentation**: Update `docs/` directory

## Important Notes

1. **Never commit sensitive data**:
   - Passwords
   - API keys
   - Personal information
   - Real attack targets

2. **Use .gitignore**: Already configured to ignore:
   - Virtual environments
   - Log files
   - Sensitive data
   - Test results

3. **Write clear commit messages**:
   - "Red Team: Add SQL injection scanner"
   - "Blue Team: Improve log analyzer accuracy"
   - "Shared: Add IP validation utility"

4. **Regular commits**: Commit often with meaningful messages

## Troubleshooting

### If you get authentication errors:

Use a Personal Access Token:
1. GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token with `repo` permissions
3. Use token as password when pushing

### If you have merge conflicts:

```bash
# Pull latest changes
git pull origin main

# Resolve conflicts in your editor
# Then:
git add .
git commit -m "Resolve merge conflicts"
git push origin main
```

## Project Structure on GitHub

Your repository should look like:
```
red-team-blue-team-cybersecurity/
├── .gitignore
├── README.md
├── LICENSE
├── requirements.txt
├── CONTRIBUTING.md
├── red_team/
│   ├── README.md
│   ├── port_scanner.py
│   ├── vulnerability_scanner.py
│   └── network_sniffer.py
├── blue_team/
│   ├── README.md
│   ├── log_analyzer.py
│   ├── ids.py
│   ├── firewall_monitor.py
│   └── threat_detection.py
├── shared/
│   ├── README.md
│   └── utils.py
├── docs/
│   └── README.md
└── tests/
    └── README.md
```

## Next Steps

1. ✅ Set up GitHub repository
2. ✅ Push initial code
3. ✅ Add collaborator (if sharing)
4. ✅ Start developing tools
5. ✅ Document findings in `docs/`
6. ✅ Create reports and presentations

Good luck with your cybersecurity project! 🔒

