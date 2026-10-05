from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    incident_id = db.Column(
        db.String(100),
        unique=True,
        nullable=False,
        index=True
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    risk_level = db.Column(
        db.String(20),
        default="LOW"
    )

    incident_level = db.Column(
        db.String(20),
        default="LOW"
    )

    classification = db.Column(
        db.String(150),
        nullable=True
    )

    signal_count = db.Column(
        db.Integer,
        default=0
    )

    high_risk_signal_count = db.Column(
        db.Integer,
        default=0
    )

    correlation_score = db.Column(
        db.Integer,
        default=0
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    threats = db.relationship(
        "Threat",
        backref="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )

    evidence = db.relationship(
        "Evidence",
        backref="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )

    iocs = db.relationship(
        "IOC",
        backref="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )

    responses = db.relationship(
        "ResponseAction",
        backref="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def to_dict(self):

        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "incident_level": self.incident_level,
            "classification": self.classification,
            "signal_count": self.signal_count,
            "high_risk_signal_count": (
                self.high_risk_signal_count
            ),
            "correlation_score": self.correlation_score,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at
                else None
            )
        }


class Threat(db.Model):
    __tablename__ = "threats"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "incidents.id"
        ),
        nullable=False
    )

    threat_type = db.Column(
        db.String(50),
        nullable=False
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    risk_level = db.Column(
        db.String(20),
        default="LOW"
    )

    source = db.Column(
        db.String(100),
        nullable=True
    )

    details = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):

        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "source": self.source,
            "details": self.details,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }


class IOC(db.Model):
    __tablename__ = "iocs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "incidents.id"
        ),
        nullable=False
    )

    ioc_type = db.Column(
        db.String(50),
        nullable=False
    )

    value = db.Column(
        db.Text,
        nullable=False
    )

    confidence = db.Column(
        db.Integer,
        default=0
    )

    source = db.Column(
        db.String(100),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):

        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "incidents.id"
        ),
        nullable=False
    )

    event_id = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    evidence_type = db.Column(
        db.String(50),
        nullable=False
    )

    evidence_hash = db.Column(
        db.String(128),
        nullable=True
    )

    previous_hash = db.Column(
        db.String(128),
        nullable=True
    )

    ledger_hash = db.Column(
        db.String(128),
        nullable=True
    )

    source = db.Column(
        db.String(100),
        nullable=True
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    risk_level = db.Column(
        db.String(20),
        default="LOW"
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):

        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "event_id": self.event_id,
            "evidence_type": self.evidence_type,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "ledger_hash": self.ledger_hash,
            "source": self.source,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }


class ResponseAction(db.Model):
    __tablename__ = "response_actions"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "incidents.id"
        ),
        nullable=False
    )

    phase = db.Column(
        db.String(50),
        nullable=False
    )

    action = db.Column(
        db.Text,
        nullable=False
    )

    priority = db.Column(
        db.String(20),
        default="MEDIUM"
    )

    status = db.Column(
        db.String(30),
        default="RECOMMENDED"
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):

        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "phase": self.phase,
            "action": self.action,
            "priority": self.priority,
            "status": self.status,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }


def initialize_database(app):

    db.init_app(app)

    with app.app_context():

        db.create_all()

    return db