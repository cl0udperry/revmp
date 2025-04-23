from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

#1. Applications Table (Uses Blackduck's UUID as a primary key)
class Application(Base):
    __tablename__="applications"
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    uuid = Column(String, unique=True, nullable=False) # Use Blackduck Project UUID as the primary key
    name = Column(String, index=True, unique=True, nullable=False) #Application Name

    #Relationships
    commits = relationship("Commit", back_populates="application", cascade="all, delete-orphan")

#2. Commits Table(Tracks vulnerabilities per release/branch)
class Commit(Base):
    __tablename__ = "commits"

    # Internal primary key (auto-incremented)
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to Application's UUID (external source ID)
    application_uuid = Column(String, ForeignKey("applications.uuid"), nullable=False)

    # External commit identifier (from Bitbucket)
    bitbucket_commit_id = Column(String, unique=True, nullable=False)
    
    release_name = Column(String, nullable = False)
    status = Column(String, default="In Development") 
    commit_date = Column(DateTime, default = datetime.now)
    critical = Column(Integer)
    high = Column(Integer)
    medium = Column(Integer)
    low = Column(Integer)

    #Relationships
    application = relationship("Application", back_populates="commits")
    coverity_vulnerabilities = relationship("CoverityVulnerability", back_populates="commit", cascade="all, delete-orphan")
    blackduck_vulnerabilities = relationship("BlackduckVulnerability", back_populates="commit", cascade="all, delete-orphan")

#3. Coverity Vulnerabilities Table
class CoverityVulnerability(Base):
    __tablename__ = "coverity_vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    application_uuid = Column(String, ForeignKey("applications.uuid"), nullable = False)
    bitbucket_commit_id = Column(String, ForeignKey("commits.bitbucket_commit_id"), nullable = False)
    cid = Column(Integer, nullable=False)

    severity = Column(String, nullable = False)
    type = Column(String, nullable = False)
    status = Column(String, nullable = False) #"New", "Triaged", "Fixed", "Dismised"
    created_at = Column(DateTime, default = datetime.now) #Reconsider whether you want a default now or even this column

    #Relationships
    application = relationship("Application")
    commit = relationship("Commit", back_populates="coverity_vulnerabilities")

    #Unique constraint to avoid duplicate entries for the same issue in the same release
    __table_args__ = (UniqueConstraint("application_uuid", "bitbucket_commit_id", "cid", name="unique_coverity_vuln"),)

#4. Blackduck Vulnerabilities Table
class BlackduckVulnerability(Base):
    __tablename__ = "blackduck_vulnerabilities"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    application_uuid = Column(String, ForeignKey("applications.uuid"), nullable = False)
    bitbucket_commit_id = Column(String, ForeignKey("commits.bitbucket_commit_id"), nullable = False)
    bdsa_id = Column(String, nullable=False)
    component_name = Column(String, nullable = False)
    type = Column(String, nullable = False)
    recommended_version = Column(String, nullable = True)
    remediation_status = Column(String, nullable = False) #"NEW", "DISMISSED"
    security_comment = Column(String, nullable = True) #Reconsider whether you want a default now or even this column

    #Relationships
    application = relationship("Application")
    commit = relationship("Commit", back_populates="blackduck_vulnerabilities")

    #Unique constraint to avoid duplicate entries for the same issue in the same release
    __table_args__ = (UniqueConstraint("application_uuid", "bitbucket_commit_id", "bdsa_id", name="unique_blackduck_vuln"),)