# llm_clients/openai_client.py
import time
from typing import Tuple, List, Dict, Any, Optional
from openai import OpenAI
import openai

class OpenAIClient:
    def __init__(self):
        self.client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key="aa",
        )

    def call_from_messages(
        self,
        messages: List[Dict[str, Any]],
        extra_create_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, int, int]:
        extra_create_kwargs = extra_create_kwargs or {}
        retry_time = 0
        while True:
            try:
                resp = self.client.chat.completions.create(
                    model="openai/gpt-oss-120b",
                    messages=messages,
                    temperature=0,
                    **extra_create_kwargs,
                )
                usage = getattr(resp, "usage", None)
                usage_dict = usage.to_dict() if (usage and hasattr(usage, "to_dict")) else {}
                itoks = usage_dict.get("prompt_tokens", 0)
                otoks = usage_dict.get("completion_tokens", 0)
                content = resp.choices[0].message.content or ""
                return content.strip(), itoks, otoks
            except openai.RateLimitError:
                retry_time += 1
                print(f"Rate limit error, retrying ({retry_time})...")
                time.sleep(min(2 * retry_time, 10))
            except Exception as e:
                retry_time += 1
                print(f"Error occurred: {e}, retrying ({retry_time})...")
                time.sleep(min(2 * retry_time, 10))