"""The single-port UI: static assets, deep-link fallback, and API 404s."""
import pytest

from bulk_ioc_scanner import web_ui

built_only = pytest.mark.skipif(
    not web_ui.is_built(),
    reason="web UI not built; run `npm run build` in frontend/",
)


async def test_unknown_api_path_stays_json(client):
    res = await client.get("/api/definitely-not-a-route")
    assert res.status_code == 404
    assert res.headers["content-type"].startswith("application/json")
    assert "Unknown API endpoint" in res.json()["detail"]


async def test_real_api_routes_still_work(client):
    """The catch-all is registered last and must not shadow the routers."""
    assert (await client.get("/api/settings")).status_code == 200
    assert (await client.get("/health")).json()["status"] == "ok"


@built_only
async def test_root_serves_the_app(client):
    res = await client.get("/")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "<div id=\"root\">" in res.text


@built_only
@pytest.mark.parametrize("route", ["/scan", "/history", "/settings"])
async def test_deep_links_fall_back_to_index(client, route):
    """Reloading on a client-side route must not 404."""
    res = await client.get(route)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")


@built_only
async def test_public_files_are_served_verbatim(client):
    res = await client.get("/logo.svg")
    assert res.status_code == 200
    assert res.text.lstrip().startswith("<svg")


@built_only
async def test_hashed_assets_are_served(client):
    index = (await client.get("/")).text
    start = index.index("/assets/")
    asset = index[start : index.index('"', start)]

    res = await client.get(asset)
    assert res.status_code == 200
    assert len(res.content) > 0


@built_only
async def test_traversal_outside_the_web_dir_is_refused(client):
    """A path that escapes the build directory gets the app, never a file."""
    res = await client.get("/../config.py")
    assert res.status_code == 200
    assert "SettingsConfigDict" not in res.text
