import os

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import OpenAI

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
) -> AIAnalysis:
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

    if not deployment:
        raise RuntimeError(
            "AZURE_OPENAI_DEPLOYMENT ortam degiskeni tanimli degil."
        )

    client = get_client()

    response = client.responses.parse(
        model=deployment,
        store=False,
        input=prompt,
        text_format=AIAnalysis,
    )

    if response.output_parsed is None:
        raise RuntimeError(
            "Azure OpenAI gecerli structured output dondurmedi."
        )

    return response.output_parsed