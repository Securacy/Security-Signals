#cat > init_sources.py << 'EOF'
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.db.models import Base, Source, SourceType
from app.ingestion.sources import VERIFIED_FEEDS
import os

engine = create_engine(os.getenv('DATABASE_URL'))
Base.metadata.create_all(engine)
session = Session(engine)

for feed in VERIFIED_FEEDS:
    existing = session.query(Source).filter_by(name=feed['name']).one_or_none()
    if not existing:
        session.add(Source(name=feed['name'], source_type=feed['type'], url=feed['url'], config={}))

session.commit()
session.close()
print("✓ Sources initialized")

