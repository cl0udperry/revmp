from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from models import Application, Commit, CoverityVulnerability, BlackduckVulnerability
import schemas
import re
import security_integrations
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

#1. Extract application UUID from Blackduck URL
def extract_blackduck_project_uuid(blackduck_url: str) -> str:
    match = re.search(r"/projects/([^/]+)/versions/", blackduck_url)
    return match.group(1) if match else None

#2. Get an existing application
def get_application(db: Session, uuid: str):
    return db.query(Application).filter(Application.uuid == uuid).first()

#3. Get all applications
def get_all_applications(db: Session):
    return db.query(Application).all()

#4. Create an application(UUID is provided from Blackduck)
def create_application(db: Session, app_data: schemas.ApplicationCreate):
    new_app = Application(uuid=app_data.uuid, name=app_data.name)
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return new_app

#5. Create a new commit entry
def create_commit(db: Session, application_uuid: str, bitbucket_commit_id: str, version_name: str):
    new_commit = Commit(
        application_uuid=application_uuid,
        bitbucket_commit_id=bitbucket_commit_id,
        release_name=version_name,
        status="In Development" #Default
    )
    db.add(new_commit)
    db.commit()
    db.refresh(new_commit)
    return new_commit

#6. Get commits for an application (sorted by date)
def get_commits_for_application(db: Session, app_uuid: str):
    return db.query(Commit).filter(Commit.application_uuid == app_uuid).all()

#7. Get an existing commit
def get_commit(db: Session, app_uuid: str, bitbucket_commit_id: str):
    return db.query(Commit).filter(Commit.application_uuid == app_uuid, Commit.bitbucket_commit_id == bitbucket_commit_id).first()

#8. Store Blackduck vulnerabilities under the commit
def store_blackduck_vulnerabilities(db: Session, application_uuid: str, bitbucket_commit_id: str, vulnerabilities: list):
    for vuln in vulnerabilities:
        try:
            new_vuln = BlackduckVulnerability(
                application_uuid=application_uuid,
                bitbucket_commit_id=bitbucket_commit_id,
                bdsa_id=vuln.get("bdsa_id"),
                component_name=vuln.get("component_name"),
                type=vuln.get("severity"),
                remediation_status=vuln.get("remediationStatus"),
                tiso_comment=vuln.get("comment")
            )
            db.add(new_vuln)
        except Exception as e:
            logger.error(f"Error creating Blackduck vulnerability: {e}")
    db.commit()