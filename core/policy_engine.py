"""
ViziDLP Policy Engine
Evaluates detections against configurable policy rules and executes actions.

Actions:
  - "log": Log the policy match (default behavior)
  - "alert": Raise an alert for the policy match
  - "block_clipboard": Clear clipboard content using pyperclip
  - "lock_screen": Platform-safe stub (not implemented, logs to stdout)
"""

from dataclasses import dataclass
from typing import Optional

from utils.config import POLICY_RULES, SEVERITY_LEVELS


@dataclass
class PolicyAction:
    """Result of a policy evaluation."""
    action: str
    matched_rule_name: str
    triggered: bool = True


class PolicyEngine:
    """
    Evaluates detection events against a set of configurable policy rules.

    Each rule specifies:
      - name: unique identifier
      - data_categories: list of data categories that trigger this rule
      - severity_threshold: minimum severity level required
      - action: one of "log", "alert", "block_clipboard", "lock_screen"
    """

    def __init__(self, rules: list = None):
        self.rules = rules or POLICY_RULES
        print(f"[POLICY] Policy engine initialized with {len(self.rules)} rule(s).")

    def evaluate(self, detection: dict) -> Optional[PolicyAction]:
        """
        Evaluate a detection against all policy rules.

        Args:
            detection: dict with at least 'type' (or 'data_category') and 'severity' keys

        Returns:
            PolicyAction if a rule matched, None otherwise
        """
        det_category = detection.get('type') or detection.get('data_category', '')
        det_severity = detection.get('severity', 'LOW')
        det_severity_level = SEVERITY_LEVELS.get(det_severity, 0)

        for rule in self.rules:
            rule_name = rule.get('name', 'unnamed')
            rule_categories = rule.get('data_categories', [])
            rule_threshold = rule.get('severity_threshold', 'LOW')
            rule_action = rule.get('action', 'log')
            rule_threshold_level = SEVERITY_LEVELS.get(rule_threshold, 0)

            # Check if detection category matches AND severity meets threshold
            if det_category in rule_categories and det_severity_level >= rule_threshold_level:
                print(f"[POLICY] Rule '{rule_name}' matched: "
                      f"category={det_category}, severity={det_severity}, action={rule_action}")

                # Execute the action
                self._execute_action(rule_action, detection)

                return PolicyAction(
                    action=rule_action,
                    matched_rule_name=rule_name,
                    triggered=True
                )

        return None

    def _execute_action(self, action: str, detection: dict):
        """Execute the policy action."""
        if action == "log":
            print(f"[POLICY] LOG: {detection.get('type', 'unknown')} detected")

        elif action == "alert":
            print(f"[POLICY] ALERT: {detection.get('type', 'unknown')} -- "
                  f"severity={detection.get('severity', 'UNKNOWN')}")

        elif action == "block_clipboard":
            self._block_clipboard(detection)

        elif action == "kill_recorder":
            self._kill_recorder(detection)

        elif action == "block_screenshot":
            self._block_screenshot(detection)

        elif action == "lock_screen":
            self._lock_screen(detection)

    def _block_clipboard(self, detection: dict):
        """Clear clipboard content when sensitive data is detected."""
        try:
            import pyperclip
            pyperclip.copy('')
            print(f"[POLICY] CLIPBOARD BLOCKED: Cleared clipboard due to "
                  f"{detection.get('type', 'unknown')} detection")
        except ImportError:
            print("[POLICY] WARNING: pyperclip not installed -- clipboard block skipped")
        except Exception as e:
            print(f"[POLICY] Clipboard clear error: {e}")

    def _kill_recorder(self, detection: dict):
        """
        Terminate detected screen recording processes.
        Uses psutil to find and kill known recording software.
        """
        RECORDING_NAMES = {
            'obs64.exe', 'obs.exe', 'obs32.exe', 'streamlabs obs.exe',
            'bandicam.exe', 'fraps.exe', 'camtasia.exe', 'sharex.exe',
            'screencastomatic.exe', 'loom.exe',
        }
        try:
            import psutil
            killed = []
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    name = (proc.info['name'] or '').lower()
                    if name in RECORDING_NAMES:
                        proc.terminate()
                        killed.append(f"{name} (PID {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if killed:
                print(f"[POLICY] KILL_RECORDER: Terminated {len(killed)} process(es): {killed}")
            else:
                print("[POLICY] KILL_RECORDER: No active recording processes found")
        except ImportError:
            print("[POLICY] WARNING: psutil not installed -- kill_recorder skipped")
        except Exception as e:
            print(f"[POLICY] kill_recorder error: {e}")

    def _block_screenshot(self, detection: dict):
        """
        Attempt to block screenshot by overwriting clipboard.
        Also clears any image data from clipboard.
        """
        try:
            import pyperclip
            pyperclip.copy('[BLOCKED BY ViziDLP - Sensitive data detected]')
            print(f"[POLICY] SCREENSHOT BLOCKED: Clipboard overwritten due to "
                  f"{detection.get('type', 'unknown')} detection")
        except ImportError:
            print("[POLICY] WARNING: pyperclip not installed -- block_screenshot skipped")
        except Exception as e:
            print(f"[POLICY] block_screenshot error: {e}")

    def _lock_screen(self, detection: dict):
        """
        Platform-safe lock_screen stub.
        Does NOT implement OS lock calls -- logs to stdout only.
        """
        print(f"POLICY: lock_screen triggered")
        # NOTE: Actual OS screen-lock is not implemented for safety.
        # To enable, implement platform-specific lock calls here.
        raise NotImplementedError(
            "lock_screen action is a stub -- implement OS-specific lock calls "
            "for production use (e.g., ctypes.windll.user32.LockWorkStation() on Windows)"
        )

