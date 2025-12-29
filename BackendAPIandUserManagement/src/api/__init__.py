# PUBLIC_INTERFACE
def get_app():
    """Return FastAPI app instance for ASGI servers.

    Returns:
        FastAPI: configured application instance
    """
    from .main import app
    return app
