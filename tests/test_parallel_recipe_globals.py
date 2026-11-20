import threading
from importlib.metadata import requires

import pypdfium2

from aidenix_atlas import _recipe_runtime as runtime


def test_installed_package_includes_pdf_reader():
    assert any(requirement.startswith('pypdfium2>=4.30')
               for requirement in requires('aidenix-atlas'))
    assert callable(pypdfium2.PdfDocument)


def test_parallel_recipe_namespace_snapshot():
    stop = threading.Event()

    def change_globals():
        i = 0
        while not stop.is_set():
            key = '_test_parallel_%d' % (i % 50)
            setattr(runtime, key, i)
            delattr(runtime, key)
            i += 1

    worker = threading.Thread(target=change_globals, daemon=True)
    worker.start()
    try:
        for _ in range(300):
            runtime._chain_runtime()
    finally:
        stop.set()
        worker.join()
