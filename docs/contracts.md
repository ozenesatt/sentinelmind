# SentinelMind AI — Arayüz Sözleşmesi v1.0

Bu doküman Esat (Platform & Bulut) ile Sıla (Tespit & AI) arasındaki
paylaşılan arayüzü tanımlar. Değişiklik için karşı tarafın onayı gerekir.

## Tablo Sahipliği

| Tablo | YAZAN | OKUYAN |
|---|---|---|
| `events` | Esat (collector) | Sıla |
| `incidents` | Sıla (korelasyon) | Esat (actions) |
| `ai_analyses` | Sıla (AI katmanı) | Esat (Teams kartı) |
| `actions` | Esat | — |

Şema tanımı: `docs/schema.sql`

## AI Çıktı JSON Şeması

`ai_analyses.payload` alanına yazılacak yapı:

```json
{
  "schema_version": "1.0",
  "incident_id": "uuid",
  "title_tr": "SSH brute-force sonrası başarılı giriş",
  "summary_tr": "3 dakika içinde 47 başarısız kimlik doğrulama denemesi...",
  "severity": "high",
  "mitre_techniques": ["T1110.001", "T1078"],
  "affected_resources": [
    {"type": "vm", "id": "/subscriptions/.../sentinelmind-soc-vm"}
  ],
  "recommended_actions": [
    {
      "action_type": "block_ip",
      "params": {"ip": "203.0.113.44"},
      "rationale_tr": "Kaynak IP 47 başarısız denemenin tamamının kaynağı."
    }
  ],
  "kvkk": {
    "notification_required": false,
    "draft_tr": null
  },
  "generated_at": "2026-08-14T10:22:00Z"
}
```

## Kapalı Enum: `action_type`

LLM **yalnızca** şu değerleri üretebilir:

```
block_ip | disable_user | isolate_vm | close_nsg_rule | revoke_storage_key | none
```

Bu liste Sıla'nın prompt'unda birebir yer almalıdır. Liste dışı bir değer
gelirse Esat'ın actions katmanı `none`'a düşürür ve Teams kartında
"manuel inceleme gerekli" gösterir. Veritabanı seviyesinde de CHECK
kısıtı ile kilitlidir.

## PII Maskeleme Sınırı

- `events.raw` → **ham** log yazılır (adli bilişim izi korunur)
- Maskeleme → LLM çağrısından **hemen önce**, Sıla'nın katmanında
- `ai_analyses.pii_masked` → maskelemenin uygulandığını doğrular

## Değişiklik Süreci

Bu dosyada değişiklik = PR + karşı tarafın onayı. Doğrudan `main`'e push yok.  

## Onaylar

- **v1.0 — Sıla (Tespit & AI):** Onaylandı. `events` şeması risk skoru formülü için yeterli, `action_type` listesi Prowler senaryolarını karşılıyor, PII maskeleme sınırı uygulanabilir. — 29.08.2026