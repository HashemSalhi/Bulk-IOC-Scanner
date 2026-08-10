"""Abstract base class for threat intelligence providers."""
import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from bulk_ioc_scanner.models.schemas import ProviderResult

# All IOC types understood by the system
IOC_TYPES = {"md5", "sha1", "sha256", "ip", "domain", "url"}

# Hash types are unified into a "hash" capability bucket
HASH_TYPES = {"md5", "sha1", "sha256"}


class Provider(ABC):
    name: str  # unique provider identifier, e.g. "virustotal"

    # Set True by providers whose lookup_batch() issues a single (or few) network
    # request(s) for many IOCs (e.g. an API /bulk endpoint). The scanner then
    # paces it as ONE call instead of one-per-IOC, saving time and quota.
    # Providers that leave this False get the per-IOC fallback automatically.
    batch_capable: bool = False

    @abstractmethod
    def supports(self, ioc_type: str) -> bool:
        """Return True if this provider can handle the given IOC type."""

    @abstractmethod
    async def lookup(
        self,
        client: "httpx.AsyncClient",
        ioc: str,
        ioc_type: str,
    ) -> ProviderResult:
        """Perform the lookup and return a normalised ProviderResult."""

    async def lookup_batch(
        self,
        client: "httpx.AsyncClient",
        items: list[tuple[str, str]],
    ) -> list[ProviderResult]:
        """Look up many (ioc, ioc_type) pairs at once.

        Default fallback: run lookup() for each item concurrently. Providers
        backed by a real bulk endpoint should override this to issue a single
        request and set ``batch_capable = True``. The returned list must contain
        exactly one ProviderResult per input item (order need not match; the
        scanner re-keys results by ``ProviderResult.ioc``).

        A lookup that raises becomes a failed result for that IOC alone, so one
        bad indicator cannot take the rest of the batch down with it.
        """
        settled = await asyncio.gather(
            *(self.lookup(client, ioc, ioc_type) for ioc, ioc_type in items),
            return_exceptions=True,
        )
        results = []
        for (ioc, ioc_type), outcome in zip(items, settled):
            if isinstance(outcome, BaseException):
                results.append(
                    ProviderResult(
                        provider=self.name, ioc=ioc, ioc_type=ioc_type, success=False,
                        error=str(outcome), raw={"error": str(outcome)},
                    )
                )
            else:
                results.append(outcome)
        return results
