"""Small replaceable OpenAI Responses API adapter (stdlib HTTP)."""

import json
import urllib.error
import urllib.request


class ProviderError(Exception):
    pass


def output_text(response):
    return "\n".join(part["text"] for item in response.get("output", []) if item.get("type") == "message" for part in item.get("content", []) if part.get("type") == "output_text")


class OpenAIProvider:
    def __init__(self, api_key, agent_model, reviewer_model, dlp):
        self.api_key = api_key
        self.agent_model = agent_model
        self.reviewer_model = reviewer_model
        self.dlp = dlp

    def respond(self, *, model, **options):
        if not self.api_key:
            raise ProviderError("Set OPENAI_API_KEY to use live mode.")
        body = {"model": model, "store": False, **options}
        # Last boundary before any user content leaves the server for OpenAI.
        body = self.dlp.safe(body)
        request = urllib.request.Request("https://api.openai.com/v1/responses", data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}, method="POST")
        try:
            # Do not follow redirects with the Authorization header.
            opener = urllib.request.build_opener(NoRedirect())
            with opener.open(request, timeout=45) as response:
                data = json.loads(response.read(2_000_000))
            if data.get("status") != "completed":
                raise ProviderError("OpenAI response was incomplete or refused. Sensitive actions are disabled.")
            return data
        except urllib.error.HTTPError as error:
            messages = {401: "OpenAI rejected the API key.", 403: "OpenAI denied access to this model.", 404: "OpenAI model or endpoint was not found.", 429: "OpenAI rate limit or quota exceeded."}
            message = messages.get(error.code, f"OpenAI returned HTTP {error.code}.")
            error.close()
            raise ProviderError(message) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise ProviderError("OpenAI request failed or timed out. Check your connection and model configuration.") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None
