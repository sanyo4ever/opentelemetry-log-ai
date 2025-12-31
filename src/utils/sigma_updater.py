"""
Sigma Rules Auto-Updater

Checks for and optionally pulls new Sigma rules from the SigmaHQ repository.
Can run as a background task within the main service or standalone via cron.
"""

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class UpdateCheckResult:
    """Result of checking for Sigma rule updates."""
    has_updates: bool
    current_commit: str
    latest_commit: str
    commits_behind: int
    new_commits: List[Dict[str, str]]
    error: Optional[str] = None


class SigmaRulesUpdater:
    """
    Manages automatic checking and updating of Sigma rules from SigmaHQ repository.
    """

    def __init__(self, config: Dict[str, Any], on_update_callback: Optional[Callable] = None):
        """
        Initialize the Sigma rules updater.

        Args:
            config: Configuration dictionary with keys:
                - rules_path: Path to the Sigma rules git repository
                - auto_update_enabled: Whether to automatically pull updates (default: False)
                - check_interval_hours: How often to check for updates (default: 24)
                - auto_restart_on_update: Whether to trigger reload after update (default: False)
            on_update_callback: Optional callback function to call after successful update
        """
        self.rules_path = config.get('rules_path', './config/sigma_rules')
        self.auto_update_enabled = config.get('auto_update_enabled', False)
        self.check_interval_hours = config.get('check_interval_hours', 24)
        self.auto_restart_on_update = config.get('auto_restart_on_update', False)
        self.on_update_callback = on_update_callback

        self._stop_event = threading.Event()
        self._check_thread: Optional[threading.Thread] = None
        self._last_check_time: Optional[datetime] = None
        self._last_check_result: Optional[UpdateCheckResult] = None

        # Resolve rules path - handle both direct path and path within rules_path
        if os.path.isdir(os.path.join(self.rules_path, '.git')):
            self.git_repo_path = self.rules_path
        elif os.path.isdir(self.rules_path):
            # Check if parent contains .git (e.g., rules_path = ./config/sigma_rules/rules)
            parent = os.path.dirname(self.rules_path)
            if os.path.isdir(os.path.join(parent, '.git')):
                self.git_repo_path = parent
            else:
                self.git_repo_path = self.rules_path
        else:
            self.git_repo_path = self.rules_path

        logger.info(f"Sigma updater initialized (repo: {self.git_repo_path}, "
                    f"auto_update: {self.auto_update_enabled}, "
                    f"interval: {self.check_interval_hours}h)")

    def _run_git_command(self, args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
        """Run a git command in the rules repository."""
        cmd = ['git', '-C', self.git_repo_path] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

    def check_for_updates(self) -> UpdateCheckResult:
        """
        Check if there are new Sigma rules available.

        Returns:
            UpdateCheckResult with details about available updates.
        """
        try:
            # Verify it's a git repository
            if not os.path.isdir(os.path.join(self.git_repo_path, '.git')):
                return UpdateCheckResult(
                    has_updates=False,
                    current_commit='',
                    latest_commit='',
                    commits_behind=0,
                    new_commits=[],
                    error=f"Not a git repository: {self.git_repo_path}"
                )

            # Get current commit
            result = self._run_git_command(['rev-parse', 'HEAD'])
            if result.returncode != 0:
                return UpdateCheckResult(
                    has_updates=False,
                    current_commit='',
                    latest_commit='',
                    commits_behind=0,
                    new_commits=[],
                    error=f"Failed to get current commit: {result.stderr}"
                )
            current_commit = result.stdout.strip()[:7]

            # Fetch from origin
            result = self._run_git_command(['fetch', 'origin'], timeout=120)
            if result.returncode != 0:
                return UpdateCheckResult(
                    has_updates=False,
                    current_commit=current_commit,
                    latest_commit='',
                    commits_behind=0,
                    new_commits=[],
                    error=f"Failed to fetch from origin: {result.stderr}"
                )

            # Get latest commit on origin/master
            result = self._run_git_command(['rev-parse', 'origin/master'])
            if result.returncode != 0:
                # Try origin/main
                result = self._run_git_command(['rev-parse', 'origin/main'])
                if result.returncode != 0:
                    return UpdateCheckResult(
                        has_updates=False,
                        current_commit=current_commit,
                        latest_commit='',
                        commits_behind=0,
                        new_commits=[],
                        error="Failed to get origin branch"
                    )
            latest_commit = result.stdout.strip()[:7]

            # Count commits behind
            result = self._run_git_command(['rev-list', '--count', 'HEAD..origin/master'])
            if result.returncode != 0:
                result = self._run_git_command(['rev-list', '--count', 'HEAD..origin/main'])
            commits_behind = int(result.stdout.strip()) if result.returncode == 0 else 0

            # Get new commit details
            new_commits = []
            if commits_behind > 0:
                result = self._run_git_command([
                    'log', '--oneline', '--format=%h|%s|%ci',
                    'HEAD..origin/master', '-n', '20'
                ])
                if result.returncode != 0:
                    result = self._run_git_command([
                        'log', '--oneline', '--format=%h|%s|%ci',
                        'HEAD..origin/main', '-n', '20'
                    ])

                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if '|' in line:
                            parts = line.split('|', 2)
                            if len(parts) >= 2:
                                new_commits.append({
                                    'hash': parts[0],
                                    'message': parts[1],
                                    'date': parts[2] if len(parts) > 2 else ''
                                })

            self._last_check_time = datetime.now()
            self._last_check_result = UpdateCheckResult(
                has_updates=commits_behind > 0,
                current_commit=current_commit,
                latest_commit=latest_commit,
                commits_behind=commits_behind,
                new_commits=new_commits
            )

            if commits_behind > 0:
                logger.info(f"Sigma rules updates available: {commits_behind} new commits")
            else:
                logger.info("Sigma rules are up to date")

            return self._last_check_result

        except subprocess.TimeoutExpired:
            error_msg = "Git command timed out"
            logger.error(error_msg)
            return UpdateCheckResult(
                has_updates=False,
                current_commit='',
                latest_commit='',
                commits_behind=0,
                new_commits=[],
                error=error_msg
            )
        except Exception as e:
            error_msg = f"Error checking for updates: {e}"
            logger.error(error_msg, exc_info=True)
            return UpdateCheckResult(
                has_updates=False,
                current_commit='',
                latest_commit='',
                commits_behind=0,
                new_commits=[],
                error=error_msg
            )

    def pull_updates(self) -> Dict[str, Any]:
        """
        Pull the latest Sigma rules from the repository.

        Returns:
            Dictionary with 'success', 'message', and optionally 'files_changed'.
        """
        try:
            # First check current status
            check_result = self.check_for_updates()
            if check_result.error:
                return {'success': False, 'message': check_result.error}

            if not check_result.has_updates:
                return {'success': True, 'message': 'Already up to date', 'files_changed': 0}

            # Get diff stats before pulling
            result = self._run_git_command(['diff', '--stat', 'HEAD..origin/master'])
            if result.returncode != 0:
                result = self._run_git_command(['diff', '--stat', 'HEAD..origin/main'])

            diff_stats = result.stdout if result.returncode == 0 else ''

            # Pull updates
            result = self._run_git_command(['pull', 'origin', 'master'], timeout=180)
            if result.returncode != 0:
                result = self._run_git_command(['pull', 'origin', 'main'], timeout=180)

            if result.returncode != 0:
                return {
                    'success': False,
                    'message': f"Failed to pull updates: {result.stderr}"
                }

            # Count files changed from diff stats
            files_changed = 0
            if diff_stats:
                lines = diff_stats.strip().split('\n')
                if lines:
                    last_line = lines[-1]
                    if 'file' in last_line:
                        import re
                        match = re.search(r'(\d+)\s+file', last_line)
                        if match:
                            files_changed = int(match.group(1))

            logger.info(f"Sigma rules updated successfully: {check_result.commits_behind} commits, {files_changed} files changed")

            # Trigger callback if configured
            if self.on_update_callback:
                try:
                    self.on_update_callback()
                except Exception as e:
                    logger.error(f"Error in update callback: {e}")

            return {
                'success': True,
                'message': f"Updated {check_result.commits_behind} commits",
                'commits_pulled': check_result.commits_behind,
                'files_changed': files_changed,
                'new_commits': check_result.new_commits
            }

        except Exception as e:
            error_msg = f"Error pulling updates: {e}"
            logger.error(error_msg, exc_info=True)
            return {'success': False, 'message': error_msg}

    def _background_check_loop(self):
        """Background thread loop for periodic update checks."""
        logger.info(f"Starting Sigma rules update checker (interval: {self.check_interval_hours}h)")

        # Initial check after a short delay
        if not self._stop_event.wait(60):  # Wait 1 minute before first check
            self._perform_scheduled_check()

        # Regular checks
        interval_seconds = self.check_interval_hours * 3600
        while not self._stop_event.is_set():
            if self._stop_event.wait(interval_seconds):
                break
            self._perform_scheduled_check()

        logger.info("Sigma rules update checker stopped")

    def _perform_scheduled_check(self):
        """Perform a scheduled update check and optionally pull updates."""
        try:
            logger.info("Performing scheduled Sigma rules update check")
            result = self.check_for_updates()

            if result.error:
                logger.warning(f"Update check failed: {result.error}")
                return

            if result.has_updates:
                logger.info(f"Found {result.commits_behind} new Sigma rule commits")

                if self.auto_update_enabled:
                    logger.info("Auto-update enabled, pulling updates...")
                    pull_result = self.pull_updates()
                    if pull_result['success']:
                        logger.info(f"Auto-update successful: {pull_result['message']}")
                    else:
                        logger.error(f"Auto-update failed: {pull_result['message']}")
                else:
                    logger.info("Auto-update disabled. Run manual update to get new rules.")
            else:
                logger.debug("No new Sigma rules available")

        except Exception as e:
            logger.error(f"Error in scheduled update check: {e}", exc_info=True)

    def start_background_checker(self):
        """Start the background update checker thread."""
        if self._check_thread and self._check_thread.is_alive():
            logger.warning("Background checker already running")
            return

        self._stop_event.clear()
        self._check_thread = threading.Thread(
            target=self._background_check_loop,
            name="SigmaRulesUpdater",
            daemon=True
        )
        self._check_thread.start()
        logger.info("Background Sigma rules checker started")

    def stop_background_checker(self):
        """Stop the background update checker thread."""
        if not self._check_thread:
            return

        logger.info("Stopping background Sigma rules checker...")
        self._stop_event.set()
        self._check_thread.join(timeout=10)
        self._check_thread = None

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the updater."""
        return {
            'enabled': self.auto_update_enabled,
            'check_interval_hours': self.check_interval_hours,
            'last_check_time': self._last_check_time.isoformat() if self._last_check_time else None,
            'last_check_result': {
                'has_updates': self._last_check_result.has_updates,
                'current_commit': self._last_check_result.current_commit,
                'latest_commit': self._last_check_result.latest_commit,
                'commits_behind': self._last_check_result.commits_behind,
            } if self._last_check_result else None,
            'background_checker_running': self._check_thread is not None and self._check_thread.is_alive()
        }


# Standalone CLI for manual checks/updates
if __name__ == '__main__':
    import argparse
    import json

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Sigma Rules Updater')
    parser.add_argument('--path', '-p', default='./config/sigma_rules',
                        help='Path to Sigma rules repository')
    parser.add_argument('--check', '-c', action='store_true',
                        help='Check for updates')
    parser.add_argument('--pull', '-u', action='store_true',
                        help='Pull updates')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    args = parser.parse_args()

    updater = SigmaRulesUpdater({'rules_path': args.path})

    if args.check or not args.pull:
        result = updater.check_for_updates()
        if args.json:
            print(json.dumps({
                'has_updates': result.has_updates,
                'current_commit': result.current_commit,
                'latest_commit': result.latest_commit,
                'commits_behind': result.commits_behind,
                'new_commits': result.new_commits,
                'error': result.error
            }, indent=2))
        else:
            if result.error:
                print(f"Error: {result.error}")
            elif result.has_updates:
                print(f"Updates available: {result.commits_behind} new commits")
                print(f"Current: {result.current_commit} -> Latest: {result.latest_commit}")
                print("\nNew commits:")
                for commit in result.new_commits[:10]:
                    print(f"  {commit['hash']} {commit['message']}")
            else:
                print(f"Sigma rules are up to date (commit: {result.current_commit})")

    if args.pull:
        result = updater.pull_updates()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result['success']:
                print(f"Success: {result['message']}")
                if result.get('files_changed'):
                    print(f"Files changed: {result['files_changed']}")
            else:
                print(f"Failed: {result['message']}")
