# FinVault + PSSH: Predictive Shadow-State Honeypotting for Financial Agent Safety

## Overview

**FinVault** is the first end-to-end safety evaluation benchmark for financial agents in execution-grounded environments (Yang et al., arXiv:2601.07853). Unlike traditional LLM safety benchmarks that rely on static Q&A or abstract tool simulations, FinVault evaluates agents through observable business state changes in isolated sandbox environments with realistic financial workflows.

This repository extends the original FinVault framework with **Predictive Shadow-State Honeypotting (PSSH)** — a novel defense mechanism that replaces binary blocking with dynamic threat intelligence extraction. Where traditional defenses like LogicGuard immediately terminate malicious actions (losing all downstream attack information), PSSH intercepts threats into an isolated shadow environment, returns hallucinated success responses, and maps the complete multi-step attack chain for intelligence gathering.

### Key Contributions

- **PSSH (HoneypotGuard)**: 438-line implementation with 8 detection rules, severity classification (ThreatSeverity enum), shadow-state logging, and attack tree construction
- **5-Phase Comparative Evaluation**: Systematic comparison between LogicGuard (baseline) and PSSH across core attacks, multi-step chains, edge cases, threat reporting, and summary metrics
- **100% Intelligence Extraction Rate**: PSSH maps all 11 attack stages across 14 test vectors, compared to LogicGuard's 0% extraction
- **Full Attack Chain Visibility**: PSSH observes all 6 steps of a multi-step attack chain; LogicGuard terminates at step 1, missing steps 2-6

### FinVault Benchmark Features

- **31 Regulatory-Driven Financial Scenarios** across 6 business domains
- **107 High-Risk Vulnerabilities** across 5 vulnerability categories
- **856 Attack Samples** using 8 attack techniques
- **Execution-Grounded Verification** through observable database state changes

## Project Structure

```
340W/
├── README.md
├── .gitignore
├── FinVault_Source/
│   └── sandbox/
│       ├── run_demo.py                  # Unified demo runner (entry point)
│       ├── evaluate_novelty.py          # 5-phase PSSH vs LogicGuard evaluation
│       ├── generate_visualizations.py   # Paper figure generation (4 PNGs)
│       ├── defense/
│       │   ├── honeypot_guard.py        # PSSH implementation (438 lines)
│       │   ├── logic_guard/
│       │   │   └── guard.py             # LogicGuard baseline (125 lines)
│       │   ├── defense_manager.py       # Defense orchestration layer
│       │   └── language_config.py       # Multi-language support
│       ├── evaluation_run.log           # Captured evaluation output
│       ├── pssh_threat_report.json      # Generated threat intelligence report
│       ├── figures/                     # Generated paper figures
│       ├── attack_datasets/             # Attack samples (856)
│       ├── normal_datasets/             # Normal business cases (107)
│       ├── config/                      # Configuration files
│       └── sandbox_00-30/               # 31 financial scenario environments
```

## Quick Start — Running the Demo

The demo pipeline runs entirely offline with **no API keys required**. It executes the LogicGuard baseline tests, the full PSSH comparative evaluation, and generates the paper's figures.

### Prerequisites

- **Python 3.9+** (pre-installed on macOS and most Linux distros; download from [python.org](https://www.python.org/downloads/) for Windows)
- **matplotlib** (the only external dependency)

### Setup Instructions

#### macOS

```bash
git clone https://github.com/scientxst/340W.git
cd 340W/FinVault_Source

# Verify Python (macOS ships with python3, NOT python)
python3 --version

# Install matplotlib (use python3 -m pip, NOT pip)
python3 -m pip install matplotlib

# Run the demo
python3 sandbox/run_demo.py
```

> **macOS Note:** Use `python3` everywhere. The `python` and `pip` commands do not exist on modern macOS unless you install them separately. Always use `python3 -m pip install` instead of `pip install`.

#### Windows

```bash
git clone https://github.com/scientxst/340W.git
cd 340W\FinVault_Source

# Verify Python (after installing from python.org with "Add to PATH" checked)
python --version

# Install matplotlib
python -m pip install matplotlib

# Run the demo
python sandbox\run_demo.py
```

> **Windows Note:** If `python` is not recognized, open the Microsoft Store and install "Python 3.12" (free), or download from [python.org](https://www.python.org/downloads/). Make sure to check **"Add Python to PATH"** during installation. After installing, restart your terminal.

#### Linux (Ubuntu/Debian)

```bash
git clone https://github.com/scientxst/340W.git
cd 340W/FinVault_Source

# Install Python and pip if not already present
sudo apt update && sudo apt install python3 python3-pip -y

# Install matplotlib
python3 -m pip install matplotlib

# Run the demo
python3 sandbox/run_demo.py
```

### Troubleshooting

| Problem | Solution |
|---------|----------|
| `command not found: python` | Use `python3` instead (macOS/Linux) |
| `command not found: pip` | Use `python3 -m pip install` instead |
| `No module named 'matplotlib'` | Run `python3 -m pip install matplotlib` |
| `externally-managed-environment` (Ubuntu 24+) | Add `--break-system-packages` flag or use `python3 -m venv venv && source venv/bin/activate` first |
| `No module named 'gymnasium'` | Run `python3 sandbox/run_demo.py` (NOT `python3 -m sandbox.run_demo`) |
| `ModuleNotFoundError: No module named 'sandbox'` | Make sure you are in the `FinVault_Source/` directory, not `sandbox/` |
| Permission denied on pip install | Add `--user` flag: `python3 -m pip install --user matplotlib` |

### Expected Output

The demo runs three steps automatically and should end with:

```
  [PASS] LogicGuard Tests
  [PASS] PSSH Evaluation
  [PASS] Figure Generation

  All steps completed successfully.
  Results match the data reported in the IEEE research paper.
```

### Run Individual Components

```bash
# PSSH evaluation only (from FinVault_Source/ directory)
python3 sandbox/evaluate_novelty.py

# Figure generation only
python3 sandbox/generate_visualizations.py

# View generated threat report
cat sandbox/pssh_threat_report.json | python3 -m json.tool | head -30

# View generated figures (macOS)
open sandbox/figures/fig3_chain_visibility.png

# View generated figures (Windows)
start sandbox\figures\fig3_chain_visibility.png

# View generated figures (Linux)
xdg-open sandbox/figures/fig3_chain_visibility.png
```

## Key Results

### Attack Success Rates (Table I)

| Model | ASR |
|-------|:---:|
| Claude-Haiku-4.5 | 6.70% |
| GPT-4 | 28.45% |
| Qwen3-32B | 42.15% |
| Qwen3-Max | 50.00% |

Social engineering and authority impersonation attacks consistently achieve the highest success rates across all models.

### Defense Effectiveness (Table II)

| Method | Detection Rate | False Positive Rate |
|--------|:--------------:|:-------------------:|
| Security Prompting | ~89% | ~3% |
| LLaMA Guard 4 | ~61% | ~30% |
| LLaMA Guard 3 | ~37% | ~44% |
| GPT-OSS-Safeguard | ~22% | ~12% |

### LogicGuard vs. PSSH (Table III)

| Metric | LogicGuard | PSSH |
|--------|:----------:|:----:|
| Defense Strategy | Binary Block | Shadow-State |
| Hard Action Blocking | 100% | 0% |
| Intelligence Extraction | 0% | 100% |
| Multi-Step Chain Visibility | 1 step | All steps |
| Attack Trees Discovered | 0 | 1 |
| Total Stages Mapped | 0 | 11 |
| Threat Report Generation | No | Yes |

## How PSSH Works

Traditional defenses (LogicGuard) detect a malicious tool call and immediately block it. The agent stops, and any planned follow-up actions are never observed. This means defenders only see the first attack step.

PSSH takes a different approach:

1. **Intercept** — When a tool call triggers a detection rule, PSSH flags it but does not block it
2. **Fork to Shadow-State** — The environment forks into an isolated shadow copy where no real state changes occur
3. **Hallucinate Success** — PSSH returns a convincing fake success response (e.g., "Transfer of $2,000,000 completed, TXN-482917")
4. **Map the Chain** — The deceived agent continues its attack plan, revealing all subsequent steps
5. **Score and Report** — Each interception is classified by severity (LOW → CRITICAL) and compiled into a structured threat intelligence report with attack tree visualization

This approach turns every detected attack into a full intelligence-gathering session rather than a dead end.

## Configuration

Edit `config/agents_config.yaml` to configure LLM agents for the full FinVault benchmark (API keys required for attack testing against live models):

```yaml
agents:
  qwen_chat:
    provider: qwen
    model_name: qwen3_32b_chat
    base_url: http://localhost:8000/v1
    api_key: YOUR_API_KEY
    temperature: 0.6
    max_tokens: 4096
    enable_thinking: false
```

Supported providers: OpenAI, Anthropic, Qwen, DeepSeek, and more via OpenRouter.

## Citation

This project extends the FinVault benchmark. If you use this work, please cite:

```bibtex
@article{Yang_2025_Finvault,
  title={FinVault: Benchmarking Financial Agent Safety in Execution-Grounded Environments},
  author={Zhi Yang and Runguo Li and Qiqi Qiang and Jiashun Wang and Fangqi Lou and Mengping Li and Dongpo Cheng and Rui Xu and Heng Lian and Shuo Zhang and Xiaolong Liang and Xiaoming Huang and Zheng Wei and Zhaowei Liu and Xin Guo and Huacan Wang and Ronghao Chen and Liwen Zhang},
  year={2026},
  eprint={2601.07853},
  archivePrefix={arXiv},
  primaryClass={cs.AI}
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Arjun Shokeen — DS 340W, Spring 2026, Penn State IST
