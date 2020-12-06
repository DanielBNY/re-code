from sqlalchemy import Column, Integer, ForeignKey
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
