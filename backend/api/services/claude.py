import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


def generate_report(ioc_data: dict) -> str:
    prompt = f"""Você é um analista sênior de threat intelligence e antifraude.
Com base nos dados abaixo de enriquecimento de IOC via VirusTotal, escreva um relatório curto (3-5 frases) em português, em linguagem clara e direta, avaliando o nível de risco e o que o analista deve fazer.

Dados do IOC:
{ioc_data}

Inclua: tipo do IOC, contexto (país, dono, ASN se disponível), veredicto (quantos engines detectaram como malicioso), nível de risco (Baixo / Médio / Alto / Crítico) e recomendação de ação."""

    response = _client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
    )
    return response.text
