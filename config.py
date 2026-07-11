import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-cyberoptimus'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///../cyberoptimus.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
