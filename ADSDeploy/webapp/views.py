"""
Views
"""

import pika
import hmac
import hashlib

from flask import current_app, request, abort
from flask.ext.restful import Resource
from .models import db, Packet
from .exceptions import NoSignatureInfo, InvalidSignature, UnknownRepoError


class MiniRabbit(object):

    def __init__(self, url):
        self.connection = None
        self.channel = None
        self.url = url

    def __enter__(self):
        self.connection = pika.BlockingConnection(pika.URLParameters(self.url))
        self.channel = self.connection.channel()
        self.channel.confirm_delivery()
        self.channel.basic_qos(prefetch_count=1)

    def __exit__(self, type, value, traceback):
        self.connection.close()

    def publish(self, payload, exchange, route):
        self.channel.basic_publish(exchange, route, payload)


class GithubListener(Resource):
    """
    GitHub web hook logic and routes
    """

    @staticmethod
    def verify_github_signature(request=None):
        """
        Validates the GitHub webhook signature

        :param request containing the header and body
        :type: flask.request object or None
        :return: None or raise
        """

        if request is None:
            raise NoSignatureInfo("No request object given")

        sig = request.headers.get(
            current_app.config.get('GITHUB_SIGNATURE_HEADER')
        )

        if sig is None:
            raise NoSignatureInfo("No signature header found")

        digestmod, sig = sig.split('=')

        h = hmac.new(
            current_app.config['GITHUB_SECRET'],
            msg=request.data,
            digestmod=hashlib.__getattribute__(digestmod),
        )

        if h.hexdigest() != sig:
            raise InvalidSignature("Signature not validated")

        return True

    @staticmethod
    def push_rabbitmq(payload, **kwargs):
        """
        Publishes the payload received from the GitHub webhooks to the correct
        queues on RabbitMQ.
        :param payload: GitHub webhook payload
        :type payload: dict

        :param kwargs: override defaults, but do not require them
        """

        with MiniRabbit(url=current_app.config['RABBITMQ_URL']) as w:
            w.publish(
                exchange=current_app.config['EXCHANGE'],
                route=current_app.config['ROUTE'],
                payload=payload
            )

    @staticmethod
    def push_database(payload):
        """
        Puts a database entry into the backend data store using the GitHub
        payload.

        :param payload: payload containing relevant attributes for db entry
        :type payload: dict

        """

        packet = Packet(
            commit=payload['commit'],
            tag=payload['tag'],
            author=payload['author'],
            repository=payload['repository'],
            environment=payload['environment']
        )

        db.session.add(packet)
        db.session.commit()

    @staticmethod
    def parse_github_payload(request=None):
        """
        parses a GitHub webhook message to create a models.Commit instance
        If that commit is already in the database, it instead returns that
        commit
        :param request: request containing the header and body
        :return: models.Commit based on the incoming payload
        """

        if request is None:
            raise ValueError("No request object given")

        formatted_request = request.get_json(force=True)

        payload = {
            'repository': formatted_request['repository']['name'],
            'commit': formatted_request['head_commit']['id'],
            'environment': 'sandbox',
            'author': formatted_request['head_commit']['author']['username'],
            'tag': formatted_request['ref'].replace('refs/tags/', '') \
            if 'tags' in formatted_request['ref'] else None
        }

        if payload['repository'] not in current_app.config.get('WATCHED_REPOS'):
            raise UnknownRepoError("{}".format(payload['repository']))

        return payload

    def post(self):
        """
        Parse the incoming commit message, save to the backend database, and
        submit a build to the queue workers.

        This endpoint should be contacted by a GitHub webhook.
        """

        # Check the GitHub header for the correct signature
        try:
            GithubListener.verify_github_signature(request)
        except (NoSignatureInfo, InvalidSignature) as e:
            current_app.logger.warning("{}: {}".format(request.remote_addr, e))
            abort(400)

        try:
            payload = GithubListener.parse_github_payload(request)
        except UnknownRepoError, e:
            return {"Unknown repo": "{}".format(e)}, 400

        # Put a DB entry
        GithubListener.push_database(payload)

        # Submit to RabbitMQ worker
        GithubListener.push_rabbitmq(payload)

        return {'received': '{}@{}:{}'.format(payload['repository'],
                                              payload['commit'],
                                              payload['environment'])}





