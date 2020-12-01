from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Date
Base = declarative_base()


class CustomerBalance(Base):
    __tablename__ = 'customer_balance'

    id = Column(Integer, primary_key=True)
    customer = Column(String)
    balance = Column(Integer)

    def __repr__(self):
        return "<CustomerBalance(name='%s', balance='%s')>" % (
            self.customer, self.balance)


class UpdateLog(Base):
    __tablename__ = 'update_logs'

    id = Column(Integer, primary_key=True)
    date = Column(Date)

    def __repr__(self):
        return "<UpdateLog(id='%s', date='%s')>" % (
            self.id, self.date)


# A skeleton for Bearer token details
class Bearer:
    def __init__(self, refreshExpiry, accessToken, tokenType, refreshToken, accessTokenExpiry, idToken=None):
        self.refreshExpiry = refreshExpiry
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.accessTokenExpiry = accessTokenExpiry
        self.idToken = idToken
