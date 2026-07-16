# Contributing to HCI-OS

Thank you for contributing to HCI-OS. To ensure consistency, code quality, and security during development, please adhere to the following guidelines.

---

## 1. Development Environment Setup

Ensure you are using **Python 3.11+** and have virtual environment tools configured.

```bash
# Clone the repository and navigate to the project directory
cd "ET Hackathon 2.0"

# Set up and activate virtual environment
python -m venv venv
venv\Scripts\activate  # On Windows

# Install required dependencies
pip install -r hci_os/requirements.txt
```

---

## 2. Code Quality & Testing

All new code, features, or agent implementations must pass the test suite before being merged.

### Running Tests
- **Run the full test suite:**
  ```bash
  pytest
  ```
- **Run specific GNN tests:**
  ```bash
  pytest hci_os/tests/test_gnn_critic_twin.py
  pytest hci_os/tests/test_gnn_ensemble.py
  ```

---

## 3. Pre-Demo & Rehearsal Guidelines

Before presenting the prototype live:
1. Run the reset utility script to clean historical records:
   ```bash
   venv\Scripts\python -m scripts.reset_demo
   ```
2. Follow the detailed preparation checklist in [docs/demo_script.md](file:///c:/Users/saina/Videos/ET%20Hackathon%202.0/docs/demo_script.md).
3. Record rehearsal times and bug fixes in the Rehearsal Log table within the demo script document.

---

## 4. Branching & Commit Guidelines

- **Branch Naming:** Align with hackathon tickets, e.g., `36-hci-os-17-5-minute-demo-script-live-presentation...`
- **Commit Messages:** Use conventional commit structures:
  - `feat(agent): add ...`
  - `fix(model): resolve GAT shape ...`
  - `test(critic): add test case ...`
  - `docs: update readme ...`
