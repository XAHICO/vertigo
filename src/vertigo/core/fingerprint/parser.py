"""Katana output parsing and execution."""

import json
import logging
import os
import platform
import subprocess
from typing import List, Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger("vertigo.fingerprint.parser")


class KatanaParser:
    """Execute and parse Katana crawler output."""

    def __init__(self, mute: bool = False):
        self.mute = mute
        self.katana_cmd = self._find_katana()

    def _find_katana(self) -> Optional[str]:
        try:
            result = subprocess.run(["katana", "-version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return "katana"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if platform.system() == "Windows":
            possible_paths = [
                os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin", "katana.exe"),
                os.path.join(os.environ.get("GOPATH", ""), "bin", "katana.exe"),
                "C:\\Go\\bin\\katana.exe",
            ]
        else:
            possible_paths = [
                os.path.join(os.environ.get("HOME", ""), "go", "bin", "katana"),
                os.path.join(os.environ.get("GOPATH", ""), "bin", "katana"),
                "/usr/local/go/bin/katana",
            ]

        for path in possible_paths:
            if path and os.path.isfile(path):
                return path
        return None

    def run_katana(
        self,
        start_url: str,
        max_depth: int,
        concurrency: int,
        timeout: int,
        session_cookies: Optional[str] = None,
    ) -> List[Dict]:
        if not self.katana_cmd:
            install_cmd = "go install github.com/projectdiscovery/katana/cmd/katana@latest"
            path_hint = (
                "Make sure %USERPROFILE%\\go\\bin is in your PATH"
                if platform.system() == "Windows"
                else "Make sure ~/go/bin is in your PATH"
            )
            raise RuntimeError(
                f"Katana not found. Install with: {install_cmd}\n{path_hint}"
            )

        katana_url = start_url
        parsed_start = urlparse(start_url)
        host_only = parsed_start.hostname
        scheme = parsed_start.scheme
        port = parsed_start.port

        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            katana_url = f"{scheme}://{host_only}{parsed_start.path or ''}"
            if parsed_start.query:
                katana_url += f"?{parsed_start.query}"
            logger.debug("katana_url_normalized  stripped_default_port  url=%r", katana_url)

        if host_only and host_only.lower() == "localhost":
            if port and port not in (80, 443):
                katana_url = f"{scheme}://127.0.0.1:{port}{parsed_start.path or ''}"
            else:
                katana_url = f"{scheme}://127.0.0.1{parsed_start.path or ''}"
            if parsed_start.query:
                katana_url += f"?{parsed_start.query}"
            logger.debug("katana_url_rewritten  localhost_to_loopback  url=%r", katana_url)

        flag_combinations = [["-jsonl", "-silent"], ["-silent"]]

        for flags in flag_combinations:
            is_json_mode = "-jsonl" in flags or "-j" in flags
            mode_label = "jsonl" if is_json_mode else "plain"

            cmd = [
                self.katana_cmd, "-u", katana_url,
                "-d", str(max_depth), "-c", str(concurrency),
                "-timeout", "10", "-retry", "1", "-aff",
            ] + flags

            if session_cookies:
                cmd.extend(["-H", f"Cookie: {session_cookies}"])
                logger.debug("katana_authenticated_session=True")

            logger.debug("katana_run  mode=%s  cmd=%r", mode_label, " ".join(cmd))

            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=timeout + 30, check=False, shell=False,
                )

                if result.returncode not in (0, 1):
                    logger.debug("katana_exit_code  code=%d  mode=%s", result.returncode, mode_label)
                    continue

                if not result.stdout:
                    logger.debug("katana_empty_stdout  mode=%s", mode_label)
                    continue

                results = []
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if is_json_mode:
                        try:
                            data = json.loads(line)
                            if data.get("error"):
                                logger.debug("katana_entry_error  error=%r", str(data["error"])[:120])
                                continue
                            url = (
                                data.get("request", {}).get("endpoint", "") or
                                data.get("response", {}).get("url", "") or
                                data.get("url", "")
                            )
                            method = (
                                data.get("request", {}).get("method", "") or
                                data.get("method", "GET")
                            ).upper()
                            if url:
                                results.append({"url": url, "method": method})
                        except json.JSONDecodeError:
                            if line.startswith("http"):
                                results.append({"url": line, "method": "GET"})
                    else:
                        if line.startswith("http"):
                            results.append({"url": line, "method": "GET"})

                if "localhost" in start_url.lower() and "127.0.0.1" in katana_url:
                    original_host = parsed_start.hostname
                    for r in results:
                        if "127.0.0.1" in r["url"]:
                            r["url"] = r["url"].replace("127.0.0.1", original_host, 1)

                logger.debug("katana_results  mode=%s  count=%d", mode_label, len(results))

                if results:
                    return results

                logger.debug("katana_no_results  mode=%s  trying_next_mode", mode_label)

            except subprocess.TimeoutExpired:
                logger.debug("katana_timeout  mode=%s", mode_label)
                raise TimeoutError("Katana execution timed out")
            except Exception as exc:
                logger.debug("katana_error  mode=%s  error=%r", mode_label, str(exc))
                continue

        logger.debug("katana_all_modes_failed")
        return []
