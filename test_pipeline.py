from app import create_app
from app.services.event_service import EventProcessor

app = create_app()

with app.app_context():
    processor = EventProcessor()

    event = {
        "ip": "8.8.8.8",
        "username": "admin",
        "status": "SUCCESS",
        "event_type": "LOGIN",
        "source": "Manual"
    }

    try:
        result = processor.process(event)
        print("Success! Ingestion pipeline output:")
        print(result)
    except Exception as e:
        print(f"Ingestion failed: {e}")