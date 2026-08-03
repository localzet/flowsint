import uuid
from unittest.mock import Mock

from flowsint_core.core.services.enricher_service import EnricherService


class FakeRegistry:
    def __init__(self, enrichers):
        self._enrichers = enrichers

    def list(self, exclude=None, wobbly_type=False):
        exclude = exclude or []
        return [
            enricher
            for enricher in self._enrichers
            if enricher["name"] not in exclude
        ]

    def list_by_input_type(self, input_type, exclude=None):
        exclude = exclude or []
        return [
            enricher
            for enricher in self._enrichers
            if enricher["name"] not in exclude
            and enricher["inputs"]["type"].lower() == input_type.lower()
        ]

    def list_by_categories(self):
        result = {}
        for enricher in self._enrichers:
            result.setdefault(enricher["category"], []).append(enricher)
        return result


def make_enricher(name, category="Domain", input_type="Domain", params_schema=None):
    return {
        "name": name,
        "category": category,
        "inputs": {"type": input_type},
        "params_schema": params_schema or [],
    }


def make_service(vault_secret=None):
    custom_type_repo = Mock()
    custom_type_repo.get_published_by_name_and_owner.return_value = None

    vault_service = Mock()
    vault_service.get_secret.return_value = vault_secret

    return EnricherService(
        db=Mock(),
        custom_type_repo=custom_type_repo,
        enricher_template_repo=Mock(),
        vault_service=vault_service,
    )


def test_hides_enricher_when_required_secret_is_missing(monkeypatch):
    monkeypatch.delenv("WHOXY_API_KEY", raising=False)
    user_id = uuid.uuid4()
    registry = FakeRegistry(
        [
            make_enricher(
                "domain_to_history",
                params_schema=[
                    {
                        "name": "WHOXY_API_KEY",
                        "type": "vaultSecret",
                        "required": True,
                    }
                ],
            ),
            make_enricher("domain_to_ip"),
        ]
    )

    enrichers = make_service().get_enrichers("Domain", user_id, registry)

    assert [enricher["name"] for enricher in enrichers] == ["domain_to_ip"]


def test_keeps_enricher_when_required_secret_exists_in_env(monkeypatch):
    monkeypatch.setenv("WHOXY_API_KEY", "secret")
    user_id = uuid.uuid4()
    registry = FakeRegistry(
        [
            make_enricher(
                "domain_to_history",
                params_schema=[
                    {
                        "name": "WHOXY_API_KEY",
                        "type": "vaultSecret",
                        "required": True,
                    }
                ],
            )
        ]
    )

    enrichers = make_service().get_enrichers("Domain", user_id, registry)

    assert [enricher["name"] for enricher in enrichers] == ["domain_to_history"]


def test_keeps_enricher_when_required_secret_exists_in_vault(monkeypatch):
    monkeypatch.delenv("WHOXY_API_KEY", raising=False)
    user_id = uuid.uuid4()
    registry = FakeRegistry(
        [
            make_enricher(
                "domain_to_history",
                params_schema=[
                    {
                        "name": "WHOXY_API_KEY",
                        "type": "vaultSecret",
                        "required": True,
                    }
                ],
            )
        ]
    )

    enrichers = make_service(vault_secret="secret").get_enrichers(
        "Domain", user_id, registry
    )

    assert [enricher["name"] for enricher in enrichers] == ["domain_to_history"]


def test_optional_secret_does_not_hide_enricher(monkeypatch):
    monkeypatch.delenv("PDCP_API_KEY", raising=False)
    user_id = uuid.uuid4()
    registry = FakeRegistry(
        [
            make_enricher(
                "cidr_to_ips",
                category="CIDR",
                input_type="CIDR",
                params_schema=[
                    {
                        "name": "PDCP_API_KEY",
                        "type": "vaultSecret",
                        "required": False,
                    }
                ],
            )
        ]
    )

    service = make_service()
    monkeypatch.setattr(service, "_is_docker_available", lambda: True)

    enrichers = service.get_enrichers("CIDR", user_id, registry)

    assert [enricher["name"] for enricher in enrichers] == ["cidr_to_ips"]


def test_docker_enricher_is_hidden_when_docker_is_unavailable(monkeypatch):
    user_id = uuid.uuid4()
    registry = FakeRegistry(
        [
            make_enricher("domain_to_tls"),
            make_enricher("domain_to_ip"),
        ]
    )
    service = make_service()
    monkeypatch.setattr(service, "_is_docker_available", lambda: False)

    enrichers = service.get_enrichers("Domain", user_id, registry)

    assert [enricher["name"] for enricher in enrichers] == ["domain_to_ip"]
