from fastapi import FastAPI, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.requests import Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from database import get_db
import crud, schemas
from models import Commit

app=FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

#Load Jinja2 templates
templates = Jinja2Templates(directory="templates")

#1. List Applications
@app.get("/applications/", response_class=HTMLResponse)
def list_applications(request: Request, db: Session = Depends(get_db)):
    applications = crud.get_all_applications(db)
    app_data = []

    # initialize totals
    coverity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    blackduck_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for app in applications:
        production_commit = crud.get_production_commit(db, app.uuid)
        if production_commit:
            app_data.append({
                "uuid": app.uuid,
                "name": app.name,
                "critical": crud.get_critical_vulnerabilities(db, app.uuid, production_commit.bitbucket_commit_id),
                "high": crud.get_high_vulnerabilities(db, app.uuid, production_commit.bitbucket_commit_id),
                "medium": crud.get_medium_vulnerabilities(db, app.uuid, production_commit.bitbucket_commit_id),
                "low": crud.get_low_vulnerabilities(db, app.uuid, production_commit.bitbucket_commit_id)
            })

            # Only include critical for BlackDuck
            blackduck_totals["critical"] += crud.get_blackduck_critical(db, app.uuid, production_commit.bitbucket_commit_id)

            # Coverity only starts from High
            coverity_totals["high"] += crud.get_coverity_high(db, app.uuid, production_commit.bitbucket_commit_id)
            coverity_totals["medium"] += crud.get_coverity_medium(db, app.uuid, production_commit.bitbucket_commit_id)
            coverity_totals["low"] += crud.get_coverity_low(db, app.uuid, production_commit.bitbucket_commit_id)

            # The rest of BlackDuck
            blackduck_totals["high"] += crud.get_blackduck_high(db, app.uuid, production_commit.bitbucket_commit_id)
            blackduck_totals["medium"] += crud.get_blackduck_medium(db, app.uuid, production_commit.bitbucket_commit_id)
            blackduck_totals["low"] += crud.get_blackduck_low(db, app.uuid, production_commit.bitbucket_commit_id)
        else:
            app_data.append({
                "uuid": app.uuid,
                "name": app.name,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            })
    return templates.TemplateResponse("dashboard.html", {
    "request": request,
    "applications": app_data,
    "coverity_totals": coverity_totals,
    "blackduck_totals": blackduck_totals,
    "severity_totals": {}
    })


#2. Get a Specific Application
@app.get("/applications/{app_uuid}", response_model=schemas.ApplicationResponse)
def get_application(app_uuid: str, db: Session = Depends(get_db)):
    #Retrieve details of a specific application
    app=crud.get_application(db, app_uuid)
    if not app:
        raise HTTPException(status_code=404, detail="Application Not Found")
    return app

#3. List Commits for Application
@app.get("/applications/{app_uuid}/commits/", response_class=HTMLResponse)
def list_commits(app_uuid: str, request: Request, db: Session = Depends(get_db)):
    application = crud.get_application(db, app_uuid)
    if not application:
        raise HTTPException(status_code=400, detail="Application Not Found")
    
    commits = crud.get_commits_for_application(db, app_uuid)
    if not commits:
        raise HTTPException(status_code=404, detail="No Commits Found")
    
    #Calculate the sum of vulnerabilities for each severity type
    for commit in commits:
        commit.critical = crud.get_critical_vulnerabilities(db, app_uuid, commit.bitbucket_commit_id)
        commit.high = crud.get_high_vulnerabilities(db, app_uuid, commit.bitbucket_commit_id)
        commit.medium = crud.get_medium_vulnerabilities(db, app_uuid, commit.bitbucket_commit_id)
        commit.low = crud.get_low_vulnerabilities(db, app_uuid, commit.bitbucket_commit_id)

    return templates.TemplateResponse("commit_list.html", {
        "request": request,
        "commits": commits,
        "app_uuid": app_uuid,
        "application": application
    })

#4. Process Securit Data (Fetch and Store Blackduck & Coverity vulnerailities)
@app.put("/process-security-data/")
def process_security_data(request_data: schemas.SecurityDataRequest, db: Session = Depends(get_db)):
    try:
        blackduck_url = request_data.blackduck_url
        snapshot_id = request_data.snapshot_id
        bitbucket_commit_id = request_data.bitbucket_commit_id
        version_name = request_data.version_name
        application_name = request_data.name

        # Check if a commit with the same Bitbucket commit ID already exists in the database
        existing_commit = crud.get_commit_by_bitbucket_commit_id(db, bitbucket_commit_id)
        if existing_commit:
            crud.refresh_security_scan_details(db, existing_commit.bitbucket_commit_id, blackduck_url, snapshot_id)
            app_data = {
                "application_uuid": existing_commit.application_uuid,
                "bitbucket_commit_id": existing_commit.bitbucket_commit_id,
                "critical": crud.get_critical_vulnerabilities(db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id),
                "high": crud.get_high_vulnerabilities(db, db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id),
                "medium": crud.get_medium_vulnerabilities(db, db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id),
                "low": crud.get_low_vulnerabilities(db, db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id)
            }
            return {
                "message": "Security data refreshed successfully",
                "application_data": app_data
            }
        else:
            #If a commit with the same Bitbucket Commit ID does not exist, create a new commit entry
            project_id = crud.extract_blackduck_project_uuid(blackduck_url)
            if not project_id:
                raise HTTPException(status_code=400, detail="Invalid Blackduck URL format")
            
            existing_app = crud.get_application(db, project_id)
            if not existing_app:
                app_data = schemas.ApplicationCreate(uuid=project_id, name=application_name)
                crud.create_application(db, app_data)

            commit_entry = crud.create_commit(db, project_id, bitbucket_commit_id, version_name)

            crud.refresh_security_scan_details(db, commit_entry.bitbucket_commid_id, blackduck_url, snapshot_id)

            app_data = {
                "application_uuid": existing_commit.application_uuid,
                "bitbucket_commit_id": existing_commit.bitbucket_commit_id,
                "critical": crud.get_critical_vulnerabilities(db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id),
                "high": crud.get_high_vulnerabilities(db, db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id),
                "medium": crud.get_medium_vulnerabilities(db, db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id),
                "low": crud.get_low_vulnerabilities(db, db, existing_commit.application_uuid, existing_commit.bitbucket_commit_id)
            }
            return {
                "message": "Security data processed successfully",
                "application_data": app_data
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

#5. Get all Vulnerabilities for a Commit
@app.get("/applications/{app_uuid}/commits/{bitbucket_commit_id}/vulnerabilities", name="get_vulnerabilities", response_class=HTMLResponse)
def get_vulnerabilities(request: Request, app_uuid: str, bitbucket_commit_id: str, db: Session = Depends(get_db)):
    commit = crud.get_commit(db, app_uuid, bitbucket_commit_id)
    if commit is None:
        raise HTTPException(status_code=404, detail="Commit not found")
    
    coverity_vulns = crud.get_coverity_vulnerabilities_for_commit(db, app_uuid, commit.bitbucket_commit_id)
    blackduck_vulns = crud.get_blackduck_vulnerabilities_for_commit(db, app_uuid, commit.bitbucket_commit_id)
    
    application = crud.get_application(db, app_uuid)

    # Vulnerability counts
    coverity_counts = {
        "critical": 0,  # Coverity doesn't have critical
        "high": crud.get_coverity_high(db, app_uuid, bitbucket_commit_id),
        "medium": crud.get_coverity_medium(db, app_uuid, bitbucket_commit_id),
        "low": crud.get_coverity_low(db, app_uuid, bitbucket_commit_id)
    }

    blackduck_counts = {
        "critical": crud.get_blackduck_critical(db, app_uuid, bitbucket_commit_id),
        "high": crud.get_blackduck_high(db, app_uuid, bitbucket_commit_id),
        "medium": crud.get_blackduck_medium(db, app_uuid, bitbucket_commit_id),
        "low": crud.get_blackduck_low(db, app_uuid, bitbucket_commit_id)
    }

    return templates.TemplateResponse("vulnerabilities.html", {
        "request": request,
        "app_uuid": app_uuid,
        "bitbucket_commit_id": bitbucket_commit_id,
        "commit": commit,
        "application": application,
        "coverity_vulns": coverity_vulns,
        "blackduck_vulns": blackduck_vulns,
        "coverity_counts": coverity_counts,
        "blackduck_counts": blackduck_counts
    })

#6. Get Current Prod Commit for an Application (need?)
@app.get("/applications/{app_uuid}/commits/get-curent-production-commit")
def get_current_production_commit(app_uuid: str, db: Session = Depends(get_db)):
    current_production_commit =db.query(Commit).filter(Commit.application_uuid == app_uuid, Commit.status == "In Production").first()
    if current_production_commit:
        return {"bitbucket_commit_id": current_production_commit.id}
    else:
        return {"bitbucket_commit_id": None}
    
#7. To update commit status (Important to go from dev to prod status need to furnish the logic to only have 1 in prod)
@app.put("/applications/{app_uuid}/commits/{bitbucket_commit_id}/status", response_model=None)
def update_status(request_data:schemas.StatusDataRequest, app_uuid: str, bitbucket_commit_id: str, db: Session = Depends(get_db)):
    status = request_data.status
    valid_status_values = ["In Development", "In Production", "Archived"]
    if status not in valid_status_values:
        raise HTTPException(status_code=400, detail="Invalid status value")

    commit = crud.get_commit_by_bitbucket_commit_id(db, bitbucket_commit_id)

    if commit:
        #Check if the new status is "In Production" and update the current "In Production commit to "Archived"
        if status == "In Production":
            get_current_production_commit = crud.get_production_commit(db, app_uuid)
            if get_current_production_commit and get_current_production_commit.bitbucket_commit_id != bitbucket_commit_id:
                get_current_production_commit.status = "Archived"
                db.commit()
        #Update the commit status
        commit.status = status
        db.commit()
        return {"message": "Status updated successfully"}
    else:
        raise HTTPException(status_code=404, detail="Commit Not Found")
