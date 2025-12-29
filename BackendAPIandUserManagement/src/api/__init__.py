# PUBLIC_INTERFACE
def get_app():
    """Return FastAPI app instance for ASGI servers."""
    from .main import app
    return app
