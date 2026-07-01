"""Setting model for key-value application configuration storage."""

from app.extensions import db


class Setting(db.Model):
    """Key-value settings store for application configuration."""

    __tablename__ = 'settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    description = db.Column(db.String(255))

    def to_dict(self) -> dict:
        """Serialize the setting to a dictionary.

        Returns:
            dict: Dictionary representation of the setting.
        """
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'description': self.description,
        }
