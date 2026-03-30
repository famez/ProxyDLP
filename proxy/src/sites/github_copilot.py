from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any

from mitmproxy import ctx, http

from proxy import Site, ProxyCallbacks, EmailNotFoundException, decode_jwt, extract_substring_between

SESSION_TTL: int = 600  # 10 minutes

_EXT_TO_LANG: dict[str, str] = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.jsx': 'javascript',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.c': 'c',
    '.h': 'cpp',
    '.hpp': 'cpp',
    '.java': 'java',
    '.cs': 'csharp',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.sh': 'bash',
    '.bash': 'bash',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.md': 'markdown',
    '.html': 'html',
    '.css': 'css',
    '.sql': 'sql',
    '.kt': 'kotlin',
    '.swift': 'swift',
    '.scala': 'scala',
    '.r': 'r',
    '.lua': 'lua',
    '.xml': 'xml',
    '.toml': 'toml',
    '.cmake': 'cmake',
    '.dockerfile': 'dockerfile',
}


def _ext_to_language(file_path: str) -> str:
    name = os.path.basename(file_path).lower()
    if name == 'dockerfile':
        return 'dockerfile'
    ext = os.path.splitext(name)[1]
    return _EXT_TO_LANG.get(ext, 'plaintext')


def _parse_copilot_prompt(prompt: str) -> dict[str, Any] | None:
    """
    Parse a GitHub Copilot inline completion prompt that contains special tokens
    (<|recently_viewed_code_snippets|>, <|current_file_content|>, etc.) into a
    structured dict suitable for rich display in the web UI.

    Returns None when the prompt contains no Copilot-specific tokens.
    """
    if '<|' not in prompt:
        return None

    result: dict[str, Any] = {}

    # --- Recently viewed snippets ---
    snippets_block = extract_substring_between(
        prompt,
        '<|recently_viewed_code_snippets|>',
        '<|/recently_viewed_code_snippets|>',
    )
    if snippets_block:
        snippets: list[dict[str, str]] = []
        for match in re.finditer(
            r'<\|recently_viewed_code_snippet\|>(.*?)<\|/recently_viewed_code_snippet\|>',
            snippets_block,
            re.DOTALL,
        ):
            snippet_text = match.group(1).strip()
            fp_match = re.match(r'code_snippet_file_path:\s*(.+?)(?:\s*\(truncated\))?\n', snippet_text)
            if fp_match:
                file_path = fp_match.group(1).strip()
                code = snippet_text[fp_match.end():].strip()
                snippets.append({
                    'file_path': file_path,
                    'language': _ext_to_language(file_path),
                    'code': code,
                })
        if snippets:
            result['recently_viewed_snippets'] = snippets

    # --- Current file content ---
    current_file_block = extract_substring_between(
        prompt, '<|current_file_content|>', '<|/current_file_content|>'
    ).strip()
    if current_file_block:
        fp_match = re.match(r'current_file_path:\s*(.+)\n', current_file_block)
        if fp_match:
            file_path = fp_match.group(1).strip()
            code = current_file_block[fp_match.end():].strip()
            result['current_file'] = {
                'file_path': file_path,
                'language': _ext_to_language(file_path),
                'code': code,
            }

    # --- Edit diff history ---
    diff_block = extract_substring_between(
        prompt, '<|edit_diff_history|>', '<|/edit_diff_history|>'
    ).strip()
    if diff_block:
        result['edit_diff_history'] = diff_block

    # --- Code to edit (with cursor marker stripped) ---
    code_to_edit = extract_substring_between(
        prompt, '<|code_to_edit|>', '<|/code_to_edit|>'
    )
    if code_to_edit.strip():
        result['code_to_edit'] = code_to_edit.replace('<|cursor|>', '').strip()

    # --- Plain-text user question (everything outside special-token blocks) ---
    plain_text = re.sub(r'<\|[^|]+\|>.*?<\|/[^|]+\|>', '', prompt, flags=re.DOTALL)
    plain_text = re.sub(r'<\|[^|]+\|>', '', plain_text).strip()
    if plain_text:
        result['user_question'] = plain_text

    return result if result else None


class Github_Copilot(Site):

    def __init__(self, urls: list[str], callbacks: ProxyCallbacks) -> None:
        super().__init__("Github Copilot", urls, callbacks)
        self.related_user_data: dict[str, dict[str, Any]] = {}
        self._related_user_data_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale(), name="gh-copilot-cleanup")

    async def _cleanup_stale(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale: list[str] = [k for k, ts in list(self._related_user_data_ts.items()) if now - ts > SESSION_TTL]
            for k in stale:
                self.related_user_data.pop(k, None)
                self._related_user_data_ts.pop(k, None)

    async def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "githubcopilot.com/chat/completions" in flow.request.pretty_url:
            ctx.log.info(f"Request URL: {flow.request.pretty_url}")

            try:
                json_body: dict[str, Any] = flow.request.json()

                if 'messages' in json_body:
                    messages: list[dict[str, Any]] = json_body['messages']
                    for message in reversed(messages):
                        if 'role' in message and message['role'] == 'user':
                            if 'content' in message:
                                prompt: str = message['content']

                                if prompt:
                                    ctx.log.info(f"Prompt found: {prompt}")

                                    ip_address: str = flow.client_conn.address[0]

                                    copilot_context = _parse_copilot_prompt(prompt)
                                    metadata = {'copilot_context': copilot_context} if copilot_context else None

                                    login: str | None = self.related_user_data.get(ip_address, {}).get("login", None)
                                    if login:
                                        await self.conversation_callback(login, prompt, metadata=metadata)
                                    else:
                                        await self.anonymous_conversation_callback(prompt, metadata=metadata)

                                break
                            else:
                                ctx.log.error("User message content not found.")
                        else:
                            ctx.log.error("User role not found in the message.")

            except json.JSONDecodeError:
                ctx.log.info(f"Request body could not be decoded as JSON")


    async def on_response_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "GET" and "api.github.com/user" in flow.request.pretty_url:

            ip_address: str = flow.client_conn.address[0]
            if "application/json" in flow.response.headers.get("content-type", ""):
                try:
                    json_body: dict[str, Any] = json.loads(flow.response.get_text())
                    if 'login' in json_body:
                        user_login: str = json_body['login']
                        ctx.log.info(f"User login: {user_login}")

                        self.related_user_data[ip_address] = {"login": user_login}
                        self._related_user_data_ts[ip_address] = time.time()

                except json.JSONDecodeError:
                    print("Failed to decode JSON.")
