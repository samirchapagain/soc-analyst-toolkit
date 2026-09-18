from __future__ import annotations

import hashlib
import os
import random
from abc import ABC, abstractmethod
from typing import Any

import requests


class BaseProvider(ABC):
    name = "provider"
    api_key_env = ""
    supported_types: set[str] = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    timeout = 10

    @property
    def configured(self) -> bool:
        return bool(os.getenv(self.api_key_env, "").strip()) if self.api_key_env else True

    def can_lookup(self, indicator_type: str) -> bool:
        return indicator_type in self.supported_types

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if not self.can_lookup(indicator_type):
            return {}
        response = self._request(indicator, indicator_type)
        return self.normalize(response, indicator, indicator_type)

    @abstractmethod
    def _request(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        raise NotImplementedError

    def normalize(self, data: dict[str, Any], indicator: str, indicator_type: str) -> dict[str, Any]:
        return {"provider": self.name, **data}

    def demo(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        digest = hashlib.sha256(indicator.encode()).digest()
        score = digest[0] % 101
        rng = random.Random(digest[1])
        return {
            "provider": self.name, "indicator": indicator, "type": indicator_type,
            "score": score, "verdict": "malicious" if score >= 75 else "suspicious" if score >= 40 else "clean",
            "tags": [self.name, "demo"], "country": rng.choice(["US", "DE", "GB"]) if indicator_type == "ip" else None,
            "demo": True,
        }

    @staticmethod
    def get(url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", 10)
        response = requests.get(url, **kwargs)
        response.raise_for_status()
        return response

    @staticmethod
    def post(url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", 10)
        response = requests.post(url, **kwargs)
        response.raise_for_status()
        return response
