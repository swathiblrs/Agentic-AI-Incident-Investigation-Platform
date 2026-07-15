from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.core.config import get_settings
from app.models.schemas import IncidentDomain, IncidentReport, InvestigationReport, StoredReportSummary
from app.storage.db import get_database_pool


class ReportStore:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._reports: dict[str, InvestigationReport | IncidentReport] = {}

    def save_security_report(self, report: InvestigationReport, session_id: str | None = None) -> None:
        self._reports[str(report.investigation_id)] = report
        self._save_postgres(
            investigation_id=report.investigation_id,
            incident_id=report.alert.id,
            domain=IncidentDomain.security,
            status=report.verdict.value,
            risk_score=report.risk_score,
            session_id=session_id,
            report=report.model_dump(mode="json"),
        )

    async def save_security_report_async(
        self,
        report: InvestigationReport,
        session_id: str | None = None,
    ) -> None:
        self._reports[str(report.investigation_id)] = report
        await self._save_postgres_async(
            investigation_id=report.investigation_id,
            incident_id=report.alert.id,
            domain=IncidentDomain.security,
            status=report.verdict.value,
            risk_score=report.risk_score,
            session_id=session_id,
            report=report.model_dump(mode="json"),
        )

    def save_incident_report(self, report: IncidentReport, session_id: str | None = None) -> None:
        self._reports[str(report.investigation_id)] = report
        self._save_postgres(
            investigation_id=report.investigation_id,
            incident_id=report.incident.id,
            domain=report.incident.domain,
            status=report.status.value,
            risk_score=report.risk_score,
            session_id=session_id,
            report=report.model_dump(mode="json"),
        )

    async def save_incident_report_async(self, report: IncidentReport, session_id: str | None = None) -> None:
        self._reports[str(report.investigation_id)] = report
        await self._save_postgres_async(
            investigation_id=report.investigation_id,
            incident_id=report.incident.id,
            domain=report.incident.domain,
            status=report.status.value,
            risk_score=report.risk_score,
            session_id=session_id,
            report=report.model_dump(mode="json"),
        )

    def get(self, investigation_id: str) -> InvestigationReport | IncidentReport | None:
        return self._reports.get(investigation_id)

    def list_summaries(self) -> list[StoredReportSummary]:
        summaries = []
        for report in self._reports.values():
            if isinstance(report, IncidentReport):
                summaries.append(
                    StoredReportSummary(
                        investigation_id=report.investigation_id,
                        domain=report.incident.domain,
                        title=report.incident.title,
                        status=report.status.value,
                        risk_score=report.risk_score,
                        created_at=report.created_at,
                    )
                )
            else:
                summaries.append(
                    StoredReportSummary(
                        investigation_id=report.investigation_id,
                        domain=IncidentDomain.security,
                        title=report.alert.title,
                        status=report.verdict.value,
                        risk_score=report.risk_score,
                        created_at=report.created_at,
                    )
                )
        return sorted(summaries, key=lambda item: item.created_at, reverse=True)

    def _save_postgres(
        self,
        investigation_id: UUID,
        incident_id: str,
        domain: IncidentDomain,
        status: str,
        risk_score: int,
        session_id: str | None,
        report: dict,
    ) -> None:
        if not self.settings.use_postgres:
            return
        try:
            import psycopg
            from psycopg.types.json import Jsonb

            with psycopg.connect(self.settings.database_url) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO investigations
                          (id, incident_id, domain, status, risk_score, session_id, report, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                          status = EXCLUDED.status,
                          risk_score = EXCLUDED.risk_score,
                          report = EXCLUDED.report
                        """,
                        (
                            investigation_id,
                            incident_id,
                            domain.value,
                            status,
                            risk_score,
                            session_id,
                            Jsonb(report),
                            datetime.now(UTC),
                        ),
                    )
                connection.commit()
        except Exception:
            return

    async def _save_postgres_async(
        self,
        investigation_id: UUID,
        incident_id: str,
        domain: IncidentDomain,
        status: str,
        risk_score: int,
        session_id: str | None,
        report: dict,
    ) -> None:
        if not self.settings.use_postgres:
            return
        try:
            from psycopg.types.json import Jsonb

            pool = await get_database_pool().open()
            if pool is None:
                return
            async with pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute(
                        """
                        INSERT INTO investigations
                          (id, incident_id, domain, status, risk_score, session_id, report, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                          status = EXCLUDED.status,
                          risk_score = EXCLUDED.risk_score,
                          report = EXCLUDED.report
                        """,
                        (
                            investigation_id,
                            incident_id,
                            domain.value,
                            status,
                            risk_score,
                            session_id,
                            Jsonb(report),
                            datetime.now(UTC),
                        ),
                    )
                await connection.commit()
        except Exception:
            return
