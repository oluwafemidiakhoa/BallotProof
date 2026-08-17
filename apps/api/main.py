from ballotproof.api import app
from ballotproof.source_api import router as source_router

app.include_router(source_router)

__all__ = ["app"]
