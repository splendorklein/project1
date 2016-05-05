from sqlalchemy import Column, ForeignKey, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class RealEstate(Base):
    __tablename__ = 'realestate'

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    latitude = Column(Float)
    longitude = Column(Float)





engine = create_engine('sqlite:////var/www/mywebsite/mywebsite/database/datamining.db')
 

Base.metadata.create_all(engine)
