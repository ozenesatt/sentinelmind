import os
import time

from azure.identity import (
    DefaultAzureCredential,
    get_bearer_token_provider,
)
from openai import OpenAI, RateLimitError

from rag.ai_schema import AIAnalysis


def get_client() -> OpenAI:
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")

    if not endpoint:
        raise RuntimeError(
            "AZURE_OPENAI_ENDPOINT ortam degiskeni tanimli degil."
        )

    endpoint = endpoint.rstrip("/") + "/openai/v1/"

    token_provider = get_bearer_token_provider(
        DefaultAzureCredential(),
        "https://ai.azure.com/.default",
    )

    return OpenAI(
        base_url=endpoint,
        api_key=token_provider,
    )


def analyze_with_azure(
    prompt: str,
    max_retries: int = 4,
) -> AIAnalysis:
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

    if not deployment:
        raise RuntimeError(
            "AZURE_OPENAI_DEPLOYMENT ortam degiskeni tanimli degil."
        )

    client = get_client()

    delays = [10, 20, 40, 60]

    for attempt in range(max_retries):
        try:
            response = client.responses.parse(
                model=deployment,
                input=prompt,
                text_format=AIAnalysis,
                store=False,
            )

            if response.output_parsed is None:
                raise RuntimeError(
                    "Azure OpenAI gecerli structured output dondurmedi."
                )

            return response.output_parsed

        except RateLimitError:
            if attempt == max_retries - 1:
                raise

            wait_seconds = delays[attempt]

            print(
                f"Azure rate limit alindi. "
                f"{wait_seconds} saniye bekleniyor..."
            )

            time.sleep(wait_seconds)

    raise RuntimeError(
        "Azure OpenAI retry dongusu beklenmedik sekilde sonlandi."
    )