import os
from pathlib import Path

basedir = Path(__file__).parent.resolve()


class Config:
    # main config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'a different hard to guess string'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']

    # gmail authentication
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    # mail accounts
    GOLFER_MAIL_SUBJECT_PREFIX = '[Golfer]'
    GOLFER_MAIL_SENDER = 'Golfer Admin <Golfer@example.com>'
    GOLFER_ADMIN = os.environ.get('GOLFER_ADMIN')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + str(Path(basedir, 'data-dev.sqlite'))


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite://'


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + str(Path(basedir, 'data.sqlite'))


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}