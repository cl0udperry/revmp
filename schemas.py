from pydantic import BaseModel
from typing import Any, List, Optional
from datetime import datetime

#1. Application Schemas
class ApplicationBase(BaseModel):
    name: str

class ApplicationCreate(ApplicationBase):
    '''Schema for creating a new Application (inherits name and optional Blackduck Project UUID)'''
    uuid: str

class ApplicationResponse(ApplicationBase):
    """Schema for returning Application infor along with metadata and related vulnerabilities"""
    uuid: str
    commits: Optional[List["CommitResponse"]] = []

    class Config:
        orm_mode = True # Enables ORM compatibility (e.g. with SQLAlchemy models)

#2. Commit Schemas
class CommitBase(BaseModel):
    release_name: str
    status: Optional[str] = "In Development"

class CommitCreate(CommitBase):
    application_uuid: str
    bitbucket_commit_id: str

class CommitResponse(CommitBase):
    id: int
    commit_date: datetime
    application_uuid: str
    bitbucket_commit_id: str

    class Config:
        orm_mode = True

#3. Coverity Vulnerability Schema
class CoverityVulnerabilityBase(BaseModel):
    cid: int
    severity: str
    type: str
    status: str
    bitbucket_commit_id: str
    application_uuid: str

class CoverityVulnerabilityCreate(CoverityVulnerabilityBase):
    """Schema for creating Coverity Vulnerability with database ID and timestamp."""
    pass

class CoverityVulnerabilityResponse(CoverityVulnerabilityBase):
    """Schema for returning Coverity vulnerability info with databse ID and timestamp."""
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True
    
#4. Blackduck vulnerability Schema
class BlackduckVulnerabilityBase(BaseModel):
    bdsa_id: str
    component_name_name: str
    severity: str
    remediation_status: str
    bitbucket_commit_id: str
    application_uuid: str

class BlackduckVulnerabilityCreate(BlackduckVulnerabilityBase):
    """Schema for creating a new Blackduck vulnerability record"""
    pass

class BlackduckVulnerabilityResponse(BlackduckVulnerabilityBase):
    """Schema for returning vulnerability info with database ID and timestamp"""
    id: int
    created_at: datetime

    class Config:
        orm_mode = True                                 

#5. Security Data Processing Request Schema
class SecurityDataRequest(BaseModel):
    blackduck_url: str
    snapshot_id: int
    bitbucket_commit_id: str
    version_name: str
    name: str