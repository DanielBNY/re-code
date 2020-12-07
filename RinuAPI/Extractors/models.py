from sqlalchemy import Column, Integer, ForeignKey, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()
extractor_engine = create_engine('sqlite:///db.Extractor')
extractor_session = sessionmaker(bind=extractor_engine)


class FunctionNode(Base):
    __tablename__ = 'FunctionNode'
    address = Column(Integer, primary_key=True)


class FunctionEdge(Base):
    __tablename__ = 'FunctionEdge'
    edge_id = Column(Integer, primary_key=True)
    source_function = Column(ForeignKey('FunctionNode.address'), nullable=False)
    called_function = Column(ForeignKey('FunctionNode.address'), nullable=False)


class FileSection(Base):
    __tablename__ = 'FileSection'
    number = Column(Integer, primary_key=True)
    name = Column(String)
    physical_start_address = Column(Integer)
    physical_end_address = Column(Integer)
    virtual_start_address = Column(Integer)
    virtual_end_address = Column(Integer)
    permission_read = Column(Boolean)
    permission_write = Column(Boolean)
    permission_execute = Column(Boolean)
