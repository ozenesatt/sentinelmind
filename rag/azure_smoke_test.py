from openai import OpenAI
from azure.identity import (
    DefaultAzureCredential,
    get_bearer_token_provider,
)


ENDPOINT = (
    "https://sentinelmind-openai-1469-2d270.openai.azure.com/"
)

DEPLOYMENT = "sentinelmind-gpt4o"


token_provider = get_bearer_token_provider(
    DefaultAzureCredential(),
    "https://ai.azure.com/.default",
)

client = OpenAI(
    base_url=ENDPOINT.rstrip("/") + "/openai/v1/",
    api_key=token_provider,
)

response = client.responses.create(
    model=DEPLOYMENT,
    input=(
        "Reply with exactly this text and nothing else: "
        "SENTINELMIND_AZURE_OK"
    ),
    store=False,
)

print("Azure inference response:")
print(response.output_text)