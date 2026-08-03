"""
Enricher service for managing enricher operations.
"""

import os
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from ..repositories import CustomTypeRepository, EnricherTemplateRepository
from .base import BaseService
from .vault_service import VaultService


class EnricherService(BaseService):
    """
    Service for enricher operations and listing.
    """

    DOCKER_REQUIRED_ENRICHERS = {
        "asn_to_cidrs",
        "cidr_to_ips",
        "domain_to_asn",
        "domain_to_tls",
        "ip_to_asn",
        "ip_to_ports",
        "org_to_asn",
    }

    def __init__(
        self,
        db: Session,
        custom_type_repo: CustomTypeRepository,
        enricher_template_repo: EnricherTemplateRepository,
        vault_service: VaultService,
        **kwargs,
    ):
        super().__init__(db, **kwargs)
        self._custom_type_repo = custom_type_repo
        self._enricher_template_repo = enricher_template_repo
        self._vault_service = vault_service
        self._docker_available: Optional[bool] = None

    @staticmethod
    def _required_secret_names(enricher: Dict[str, Any]) -> List[str]:
        return [
            param["name"]
            for param in enricher.get("params_schema", [])
            if param.get("type") == "vaultSecret" and param.get("required", False)
        ]

    def _has_secret(self, user_id: UUID, secret_name: str) -> bool:
        if os.getenv(secret_name):
            return True

        try:
            return self._vault_service.get_secret(user_id, secret_name) is not None
        except Exception:
            return False

    def _is_docker_available(self) -> bool:
        if self._docker_available is not None:
            return self._docker_available

        try:
            import docker

            client = docker.from_env()
            client.ping()
            self._docker_available = True
        except Exception:
            self._docker_available = False

        return self._docker_available

    def _has_runtime_requirements(self, enricher: Dict[str, Any]) -> bool:
        if enricher.get("name") in self.DOCKER_REQUIRED_ENRICHERS:
            return self._is_docker_available()

        return True

    def _filter_available_enrichers(
        self, enrichers: List[Dict[str, Any]], user_id: UUID
    ) -> List[Dict[str, Any]]:
        secret_cache: Dict[str, bool] = {}

        def has_secret(secret_name: str) -> bool:
            if secret_name not in secret_cache:
                secret_cache[secret_name] = self._has_secret(user_id, secret_name)
            return secret_cache[secret_name]

        return [
            enricher
            for enricher in enrichers
            if self._has_runtime_requirements(enricher)
            and all(
                has_secret(secret_name)
                for secret_name in self._required_secret_names(enricher)
            )
        ]

    def is_enricher_available(
        self, enricher_name: str, user_id: UUID, enricher_registry
    ) -> bool:
        enrichers = [
            enricher
            for enricher in enricher_registry.list()
            if enricher.get("name") == enricher_name
        ]
        return bool(self._filter_available_enrichers(enrichers, user_id))

    def get_enrichers(
        self, category: Optional[str], user_id: UUID, enricher_registry
    ) -> List[Dict[str, Any]]:
        if not category or category.lower() == "undefined":
            return self._filter_available_enrichers(
                enricher_registry.list(exclude=["n8n_connector"]), user_id
            )

        custom_type = self._custom_type_repo.get_published_by_name_and_owner(
            category, user_id
        )

        if custom_type:
            return []
            return enricher_registry.list(exclude=["n8n_connector"], wobbly_type=True)

        return self._filter_available_enrichers(
            enricher_registry.list_by_input_type(
                category, exclude=["n8n_connector"]
            ),
            user_id,
        )

    def get_enrichers_by_categories(
        self, user_id: UUID, enricher_registry
    ) -> Dict[str, List[Dict[str, Any]]]:
        enrichers_by_category = {}

        for category, enrichers in enricher_registry.list_by_categories().items():
            available_enrichers = self._filter_available_enrichers(
                enrichers, user_id
            )
            if available_enrichers:
                enrichers_by_category[category] = available_enrichers

        return enrichers_by_category

    def get_all_enrichers(
        self, category: Optional[str], user_id: UUID, enricher_registry
    ) -> list:
        base_enrichers = self.get_enrichers(category, user_id, enricher_registry)
        template_enrichers = self._enricher_template_repo.get_by_owner(
            user_id, category
        )
        return [*base_enrichers, *template_enrichers]


def create_enricher_service(db: Session) -> EnricherService:
    return EnricherService(
        db=db,
        custom_type_repo=CustomTypeRepository(db),
        enricher_template_repo=EnricherTemplateRepository(db),
        vault_service=VaultService(db=db),
    )
