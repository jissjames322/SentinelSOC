import logging
from app.parsers.factory import ParserFactory
from app.services.event_service import EventProcessor

logger = logging.getLogger(__name__)

class ImportService:
    """Service to handle importing files through corresponding log parsers and processing pipeline."""

    def __init__(self):
        self.processor = EventProcessor()

    def import_file(self, filepath: str, source: str) -> dict:
        """Parses a log file using the registered parser and processes all events through the security pipeline."""
        logger.info(f"Starting import from file: {filepath} using source parser: {source}")
        
        try:
            parser = ParserFactory.get_parser(source)
        except ValueError as e:
            logger.error(str(e))
            return {
                "total": 0,
                "imported": 0,
                "failed": 0,
                "error": str(e)
            }

        try:
            events = parser.parse(filepath)
        except Exception as e:
            logger.exception(f"Error parsing log file {filepath}")
            return {
                "total": 0,
                "imported": 0,
                "failed": 0,
                "error": f"Parsing failed: {str(e)}"
            }

        imported_count = 0
        failed_count = 0

        for idx, event in enumerate(events):
            try:
                # Add default source matching if not set by parser
                if not event.get("source"):
                    event["source"] = source.upper()
                
                self.processor.process(event)
                imported_count += 1
            except Exception as e:
                logger.error(f"Failed to process event #{idx} from log file: {str(e)}")
                failed_count += 1

        logger.info(f"Import completed for {filepath}. Parsed: {len(events)}, Imported: {imported_count}, Failed: {failed_count}")
        
        return {
            "total": len(events),
            "imported": imported_count,
            "failed": failed_count
        }

    def import_bulk_ips(self, filepath: str) -> dict:
        """Reads a list of IP addresses line-by-line and processes them through the ingestion pipeline."""
        logger.info(f"Starting bulk IP import from file: {filepath}")
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            logger.exception(f"Error reading bulk IP file {filepath}")
            return {
                "total": 0,
                "imported": 0,
                "failed": 0,
                "error": f"Failed to read file: {str(e)}"
            }

        imported_count = 0
        failed_count = 0
        total_count = 0

        for line in lines:
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            
            total_count += 1
            event = {
                "ip": ip,
                "username": "bulk-upload",
                "status": "SUCCESS",
                "event_type": "BULK_LOOKUP",
                "source": "BULK_FILE",
                "description": "Bulk IP intelligence import"
            }
            
            try:
                self.processor.process(event)
                imported_count += 1
            except Exception as e:
                logger.error(f"Failed to process bulk IP {ip}: {str(e)}")
                failed_count += 1

        logger.info(f"Bulk IP import completed. Total: {total_count}, Imported: {imported_count}, Failed: {failed_count}")
        return {
            "total": total_count,
            "imported": imported_count,
            "failed": failed_count
        }