"""
Application factory
"""

import logging.config
import os

from flask import Flask
from flask.ext.restful import Api
from views import GithubListener, RabbitMQListener
from .models import db


def create_app(name='ADSDeploy'):
    """
    Create the application

    :param name: name of the application
    :return: flask.Flask application
    """

    app = Flask(name, static_folder=None)
    app.url_map.strict_slashes = False

    # Load config and logging
    load_config(app)
    logging.config.dictConfig(
        app.config['DEPLOY_LOGGING']
    )

    # Register extensions
    api = Api(app)
    api.add_resource(GithubListener, '/webhooks', methods=['POST'])
    api.add_resource(RabbitMQListener, '/rabbit', methods=['POST'])
    db.init_app(app)

    return app


def load_config(app, basedir=os.path.dirname(__file__)):
    """
    Loads configuration in the following order:
        1. config.py
        2. local_config.py (ignore failures)
        3. consul (ignore failures)
    :param app: flask.Flask application instance
    :param basedir: base directory to load the config from
    :return: None
    """

    app.config.from_pyfile(os.path.join(basedir, 'config.py'))

    try:
        app.config.from_pyfile(os.path.join(basedir, 'local_config.py'))
    except IOError:
        app.logger.info("Could not load local_config.py")

if __name__ == '__main__':
    application = create_app()
    application.run(debug=True, use_reloader=False)
