import os
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

ACCESS_TOKEN = os.getenv("MERCADO_PAGO_ACCESS_TOKEN")
APP_PRICE = float(os.getenv("APP_PRICE", "19.99"))


def criar_assinatura_mensal(usuario_email: str):
    if not ACCESS_TOKEN:
        raise Exception("Access Token do Mercado Pago não configurado no .env")

    url = "https://api.mercadopago.com/preapproval"

    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    start_date = datetime.now(timezone.utc) + timedelta(minutes=5)
    end_date = datetime.now(timezone.utc) + timedelta(days=365 * 5)

    payload = {
        "reason": "CertFlow - Plano Mensal",
        "external_reference": usuario_email,
        "payer_email": usuario_email,
        "auto_recurring": {
            "frequency": 1,
            "frequency_type": "months",
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "transaction_amount": APP_PRICE,
            "currency_id": "BRL"
        },
        "back_url": "https://www.mercadopago.com.br",
        "status": "pending"
    }

    response = requests.post(
        url,
        headers=headers,
        json=payload,
        timeout=30
    )

    if response.status_code >= 400:
        raise Exception(
            f"Erro Mercado Pago {response.status_code}: {response.text}"
        )

    data = response.json()

    return {
        "init_point": data.get("init_point"),
        "id": data.get("id"),
        "status": data.get("status")
    }




