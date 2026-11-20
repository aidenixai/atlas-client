"""The dataset module ships with the package and a connector gets it by name."""
import gzip
import io

import httpx

from aidenix_atlas import _recipe_runtime as runtime
from aidenix_atlas import dataset


def test_connector_reads_a_dataset_from_the_package(tmp_path, monkeypatch):
    body = gzip.compress(b"company,state\nAcme,CA\nGlobex,NY\n")

    def handler(request):
        return httpx.Response(200, content=body, headers={"content-length": str(len(body))})

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setenv("ATLAS_DATASET_CACHE", str(tmp_path))
    code = ("def run(state):\n"
            "    t = dataset.open('https://example.org/x.csv.gz')\n"
            "    rows = t.query('SELECT company FROM data WHERE state = ?', [state])\n"
            "    return {'records': rows, 'count': len(rows)}\n")
    out = runtime._run_connector_step({"connector_code": code, "in": ["state"]}, {"state": "CA"})
    assert out["raw"]["records"] == [{"company": "Acme"}], out
    assert dataset.__name__ == "aidenix_atlas.dataset"
