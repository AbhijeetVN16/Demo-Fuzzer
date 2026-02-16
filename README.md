
# UDS Demo Fuzzer

A Python-based **UDS Vulnerability Scanner** for Linux using **SocketCAN + ISO-TP**, featuring a graphical control panel for automated exploit testing.

This project acts as an offensive security tool (Fuzzer) designed to audit UDS-enabled ECUs. It implements specific attack vectors including buffer overflows, sequence attacks, resource exhaustion, and logic bypasses to validate ECU robustness and security mechanisms.

---

## Features

- **Automated Exploit Execution:**
  - `V1` VIN Buffer Overflow (Payload Fuzzing)
  - `V2` Magic Byte Security Bypass
  - `V3` Resource Exhaustion (DoS Flood)
  - `V4` ISO-TP Sequence Attack (Out-of-Order Frames)
  - `V5` Diagnostic Session Leak
  - `V6` Weak Security Seed Detection
- **ISO-TP Communication:** Abstracted transport layer using `isotp` and `python-can`.
- **Graphical Dashboard (Tkinter):**
  - One-click attack triggering.
  - Real-time ECU status monitoring (Alive/Dead check).
  - Detailed attack logging and result analysis.
- **Health Monitoring:** Automatically detects if the target ECU crashes or hangs following an attack.

---

## Project Structure

```text
FUZZER/
│
├── main.py                  # Entry point (GUI)
├── uds_controller.py        # SocketCAN + ISO-TP transport abstraction
├── vulnerability_tests.py   # Attack logic and exploit implementations
└── requirements.txt         # Dependencies
├── uds_controller.py        # ISO-TP + CAN transport + send/recv helpers
├── vulnerability_tests.py   # Vulnerability test cases (V1 to V6)
```

## File Overview

- **main.py**  
  Entry point. Starts the GUI application. Handles threading for attacks and updates the visual dashboard with scan results.

- **uds_controller.py**  
  Handles the low-level CAN bus interaction. It manages the ISO-TP socket setup and provides the `send_recv()` and `check_alive()` primitives.

- **vulnerability_tests.py**  
  Inherits from the controller to implement specific exploit logic. It defines the payload structures for all 6 supported vulnerabilities (V1–V6).


## Requirements

**System**
* **Linux** (recommended: Ubuntu/Debian)
* **SocketCAN** support (kernel modules)

**Python Dependencies**
Install required packages using:

```bash
pip3 install -r requirements.txt
```

Note: Tkinter is usually pre-installed on Linux. If missing:
```bash
sudo apt-get install python3-tk
```
## Setup & Usage
**1. Setup Virtual CAN (vcan0)**

Before running the simulator, create a virtual CAN interface:
```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```
**2. Run the Simulator**

From inside the project directory:
```bash
python3 main.py
```
## Implemented Attacks

The scanner supports **6 specific vulnerability tests**. Clicking a button in the GUI triggers the corresponding **threaded test**.

| ID  | Attack Name            | Description |
|-----|-------------------------|-------------|
| V1  | VIN Buffer Overflow     | Sends a **WriteDataByIdentifier (`0x2E`)** request with a payload exceeding the buffer size to trigger a crash. |
| V2  | Magic Byte Bypass       | Attempts to bypass security checks by appending a specific **"magic" byte sequence** to the payload. |
| V3  | Resource DoS            | Floods the CAN bus with rapid **TesterPresent (`0x3E`)** messages to exhaust ECU processing resources. |
| V4  | ISO-TP Seq Attack       | Sends ISO-TP Consecutive Frames with manipulated **Sequence Numbers (SN)** to corrupt the reassembly process. |
| V5  | Session Leak            | Checks if the ECU allows illegal transitions between Diagnostic Sessions without security access. |
| V6  | Weak Seed Check         | Requests a security seed (`0x27`) and checks if the ECU returns a static or known weak seed (e.g., `DEADBEEF`). |

---

## Scanner Behavior

When an attack is launched, the tool performs the following steps:

1. **Attack**: Sends the malicious payload or sequence defined in `vulnerability_tests.py`.
2. **Monitor**: Waits for a response or a timeout.
3. **Health Check**: Sends a standard **TesterPresent** message to verify if the ECU is still responsive.
4. **Verdict**:
   - **CRITICAL**: If the ECU fails to respond (Crash/Hang) or returns a compromised value (e.g., Static Seed).
   - **INFO**: If the ECU handles the attack gracefully.

---

## Logs

The GUI provides a centralized scrolling log:

- **ATTACK**: Indicates the start of an exploit attempt.
- **CRITICAL**: Highlights successful exploits (ECU crashed, vulnerability found).
- **INFO**: General status updates and "Passed" tests.

---

## Notes

- Designed to work in tandem with a vulnerable ECU simulator (via `vcan0`).
- To target real hardware, modify the interface parameter in `uds_controller.py`.
- Ensure you have permission to audit the target ECU before running these tests.

---

## License

Intended for academic and research use.



