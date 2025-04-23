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
            type = vuln.get("severity") or "NA"
            remediation_status = vuln.get("remediationStatus") or "NA"
            new_vuln = BlackduckVulnerability(
                application_uuid=application_uuid,
                bitbucket_commit_id=bitbucket_commit_id,
                bdsa_id=vuln.get("bdsa_id"),
                component_name=vuln.get("component_name"),
                type=type,
                remediation_status=remediation_status,
                security_comment=vuln.get("comment")
            )
            db.add(new_vuln)
        except Exception as e:
            logger.error(f"Error creating Blackduck vulnerability: {e}")
    db.commit()

#9. Store Coverity Vulnerabilities under the commit
def store_coverity_vulnerabilities(db: Session, application_uuid: str, bitbucket_commit_id: str, vulnerabilities: list):
    for vuln in vulnerabilities:
        if vuln.get("cid") is not None:
            try:
                new_vuln = CoverityVulnerability(
                    application_uuid=application_uuid,
                    bitbucket_commit_id = bitbucket_commit_id,
                    cid = int(vuln.get("cid")),
                    severity = vuln.get("displayImpact"),
                    type = vuln.get("displayType"),
                    status = vuln.get("status")
                )
                db.add(new_vuln)
            except ValueError:
                logger.error(f"Invalid cid value: {vuln.get('cid')}")
    db.commit()

#10. Get Coverity vulnerabilities for a specific commit
def get_coverity_vulnerabilities_for_commit(db: Session, app_uuid: str, bitbucket_commit_id: str):
    query = db.query(CoverityVulnerability).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == bitbucket_commit_id
    )
    return query.all()

#11. Get Blackduck vulnerabilities for a specific commit
def get_blackduck_vulnerabilities_for_commit(db: Session, app_uuid: str, bitbucket_commit_id: str):
    query = db.query(BlackduckVulnerability).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == bitbucket_commit_id
    )
    return query.all()

#12, Get Production Total Count Vuln
def get_production_vulnerabilities(db: Session, app_uuid: str):
    production_commits = db.query(Commit).filter(
        Commit.application_uuid == app_uuid,
        Commit.status == "In Production"
    ).all()

    # If no commits are in production, return zero counts
    if not production_commits:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    # Get commit IDs for production commits
    production_bitbucket_commit_ids = [commit.id for commit in production_commits]

    #Fetch Coverity Issues linked to production commits
    coverity_counts = db.query(
        CoverityVulnerability.severity,
        func.count(CoverityVulnerability.id)
    ).filter(
        CoverityVulnerability.bitbucket_commit_id.in_(production_bitbucket_commit_ids)
    ).group_by(CoverityVulnerability.severity).all()

    #Fetch Blackduck Issues linked to production commits
    blackduck_counts = db.query(
        BlackduckVulnerability.type,
        func.count(BlackduckVulnerability.id)
    ).filter(
        BlackduckVulnerability.bitbucket_commit_id.in_(production_bitbucket_commit_ids)
    ).group_by(BlackduckVulnerability.type).all()

    # Initialise counts with 0 
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    #Convert query results to dictionary
    for severity, count in coverity_counts + blackduck_counts:
        severity_totals[severity.lower()] += count
    
    return severity_totals

#13. Get Production Blackduck Count
def get_production_blackduck_vulnerabilities(db: Session, app_uuid: str):
    production_commits = db.query(Commit).filter(
        Commit.application_uuid == app_uuid,
        Commit.status == "In Production"
    ).all()

    # If no commits are in production, return zero counts
    if not production_commits:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    #Get commit IDs for production commits   
    production_bitbucket_commit_ids = [commit.bitbucket_commit_id for commit in production_commits]

    #Fetch Blackduck Issues linked to profuction Commits
    blackduck_counts = db.query(
        BlackduckVulnerability.type,
        func.count(BlackduckVulnerability.id)
    ).filter(
        BlackduckVulnerability.bitbucket_commit_id.in_(production_bitbucket_commit_ids)
    ).group_by(BlackduckVulnerability.type).all()

    #Initialize counts with 0
    blackduck_severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    #Convert query results to dictionary
    for severity, count in blackduck_counts:
        if severity == "Critical":
            blackduck_severity_totals["critical"] += count
        elif severity =="High":
            blackduck_severity_totals["high"] += count
        elif severity =="Medium":
            blackduck_severity_totals["medium"] += count
        elif severity =="Low":
            blackduck_severity_totals["low"] += count

    return blackduck_severity_totals

#14. Get Production Coverity Count
def get_production_coverity_vulnerabilities(db: Session, app_uuid: str):
    production_commits = db.query(Commit).filter(
        Commit.application_uuid == app_uuid,
        Commit.status == "In Production",
    ).all()

    #If no commits are in production, return zero counts
    if not production_commits:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    # Get commit IDs for production commits
    production_bitbucket_commit_ids = [commit.bitbucket_commit_id for commit in production_commits]

    #Fetch Coverity Isues linked to production Commits
    coverity_counts = db.query(
        CoverityVulnerability.severity,
        func.count(CoverityVulnerability.id)
    ).filter(
        CoverityVulnerability.bitbucket_commit_id.in_(production_bitbucket_commit_ids)
    ).group_by(CoverityVulnerability.severity).all()

    #Initialize counts with 0
    coverity_severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    #Convert query results to dictionary
    for severity, count in coverity_counts:
        coverity_severity_totals[severity.lower()] += count

    return coverity_severity_totals

#15. To update Commit status
def update_status(db: Session, app_uuid: str, bitbucket_commit_id: str, status: str):
    db.query(Commit).filter(Commit.application_uuid == app_uuid, Commit.bitbucket_commit_id == bitbucket_commit_id).update({"status": status})
    db.commit()

def get_commit_by_bitbucket_commit_id(db: Session, bitbucket_commit_id: str):
    return db.query(Commit).filter(Commit.bitbucket_commit_id == bitbucket_commit_id).first()

def refresh_security_scan_details(db: Session, bitbucket_commit_id: str, blackduck_url: str, snapshot_id:int):
    #Delete existing Blackduck vulnerabilities
    db.query(BlackduckVulnerability).filter(BlackduckVulnerability.bitbucket_commit_id == bitbucket_commit_id).delete()

    #Delete existing Coverity Vulnerabilities
    db.query(CoverityVulnerability).filter(CoverityVulnerability.bitbucket_commit_id == bitbucket_commit_id).delete()

    commit = get_commit_by_bitbucket_commit_id(db, bitbucket_commit_id)

    if commit is None:
        raise HTTPException(status_code=404, detail="Commit not found")
    
    #Fetch Blackduck vulnerabilities
    blackduck_vulnerabilities = security_integrations.get_blackduck_vulnerabilities(blackduck_url)

    #Store blackduck vulnerabilities under the commit
    store_blackduck_vulnerabilities(db, commit.application_uuid, commit.bitbucket_commit_id, blackduck_vulnerabilities)

    #Fetch Coverity vulnerabilities
    coverity_vulnerabilities = security_integrations.get_coverity_vulnerabilities(snapshot_id)

    #Store Coverity vulnerabilities under the commit
    store_coverity_vulnerabilities(db, commit.application_uuid, commit.bitbucket_commit_id, coverity_vulnerabilities)

    #Update commit counts
    commit.critical = get_critical_vulnerabilities(db, commit.application_uuid, commit.bitbucket_commit_id)
    commit.high = get_high_vulnerabilities(db, commit.application_uuid, commit.bitbucket_commit_id)
    commit.medium = get_medium_vulnerabilities(db, commit.application_uuid, commit.bitbucket_commit_id)
    commit.low = get_low_vulnerabilities(db, commit.application_uuid, commit.bitbucket_commit_id)

    db.commit()

    #Return the counts of vulnerabilities
    blackduck_count = len(blackduck_vulnerabilities)
    coverity_count = len(coverity_vulnerabilities)

    return {
        "blackduck_count": blackduck_count,
        "coverity_count": coverity_count
    }

#Get Critical Vulnerabilities
def get_critical_vulnerabilities(db: Session, app_uuid: str, bitbucket_commit_id: str):
    critical_vulnerabilities = db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        BlackduckVulnerability.type.in_(["Critical", "CRITICAL"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).first()
    return critical_vulnerabilities[0]

#Get High Vulnerabilities
def get_high_vulnerabilities(db: Session, app_uuid: str, bitbucket_commit_id: str):
    high_vulnerabilities = db.query(func.count(CoverityVulnerability.id)).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        CoverityVulnerability.severity == "High",
        CoverityVulnerability.status.in_(["New", "NEW"])
    ).first()[0] + db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        BlackduckVulnerability.type.in_(["High", "HIGH"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).first()[0]
    return high_vulnerabilities

#Get Medium Vulnerabilities
def get_medium_vulnerabilities(db: Session, app_uuid: str, bitbucket_commit_id: str):
    medium_vulnerabilities = db.query(func.count(CoverityVulnerability.id)).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        CoverityVulnerability.severity == "Medium",
        CoverityVulnerability.status.in_(["New", "NEW"])
    ).first()[0] + db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        BlackduckVulnerability.type.in_(["Medium", "MEDIUM"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).first()[0]
    return medium_vulnerabilities

#Get Low Vulnerabilities
def get_low_vulnerabilities(db: Session, app_uuid: str, bitbucket_commit_id: str):
    low_vulnerabilities = db.query(func.count(CoverityVulnerability.id)).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        CoverityVulnerability.severity == "Low",
        CoverityVulnerability.status.in_(["New", "NEW"])
    ).first()[0] + db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == bitbucket_commit_id,
        BlackduckVulnerability.type.in_(["Low", "LOW"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).first()[0]
    return low_vulnerabilities

def get_blackduck_critical(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == commit_id,
        BlackduckVulnerability.type.in_(["Critical", "CRITICAL"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).scalar()

def get_blackduck_high(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == commit_id,
        BlackduckVulnerability.type.in_(["High", "HIGH"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).scalar()

def get_blackduck_medium(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == commit_id,
        BlackduckVulnerability.type.in_(["Medium", "MEDIUM"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).scalar()

def get_blackduck_low(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(BlackduckVulnerability.id)).filter(
        BlackduckVulnerability.application_uuid == app_uuid,
        BlackduckVulnerability.bitbucket_commit_id == commit_id,
        BlackduckVulnerability.type.in_(["Low", "LOW"]),
        BlackduckVulnerability.remediation_status.in_(["New", "NEW"])
    ).scalar()

def get_coverity_high(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(CoverityVulnerability.id)).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == commit_id,
        CoverityVulnerability.severity == "High",
        CoverityVulnerability.status.in_(["New", "NEW"])
    ).scalar()

def get_coverity_medium(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(CoverityVulnerability.id)).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == commit_id,
        CoverityVulnerability.severity == "Medium",
        CoverityVulnerability.status.in_(["New", "NEW"])
    ).scalar()

def get_coverity_low(db: Session, app_uuid: str, commit_id: str):
    return db.query(func.count(CoverityVulnerability.id)).filter(
        CoverityVulnerability.application_uuid == app_uuid,
        CoverityVulnerability.bitbucket_commit_id == commit_id,
        CoverityVulnerability.severity == "Low",
        CoverityVulnerability.status.in_(["New", "NEW"])
    ).scalar()

#Get the production commit for an application
def get_production_commit(db: Session, app_uuid: str):
    return db.query(Commit).filter(
        Commit.application_uuid == app_uuid,
        Commit.status == "In Production"
    ).first()

#Get the production vulnerabilities for an application
def get_vulnerabilities_for_commit(db: Session, app_uuid, bitbucket_commit_id: str):
    return get_production_vulnerabilities(db, app_uuid)