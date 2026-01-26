from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:
    import geoip2.database
except Exception:
    geoip2 = None  # type: ignore


@dataclass(frozen=True)
class GeoInfo:
    country_name: str = ""
    country_iso: str = ""


class GeoIpResolver:
    def __init__(self, mmdb_path: str | Path | None):
        self.mmdb_path = Path(mmdb_path) if mmdb_path else None
        self._reader = None

        if self.mmdb_path and self.mmdb_path.exists() and geoip2 is not None:
            self._reader = geoip2.database.Reader(str(self.mmdb_path))

    def lookup(self, ip: str) -> GeoInfo:
        if not self._reader:
            return GeoInfo()
        try:
            resp = self._reader.country(ip)
            return GeoInfo(
                country_name=resp.country.name or "",
                country_iso=resp.country.iso_code or "",
            )
        except Exception:
            return GeoInfo()

    def close(self) -> None:
        try:
            if self._reader:
                self._reader.close()
        except Exception:
            pass
