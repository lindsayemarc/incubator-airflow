# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import flask_login

# Need to expose these downstream
# pylint: disable=unused-import
from flask_login import (current_user,
                         logout_user,
                         login_required,
                         login_user)
# pylint: enable=unused-import

from flask import url_for, redirect, request

from flask_oauthlib.client import OAuth

from airflow import models, configuration, settings
from airflow.utils.db import provide_session
import logging

_log = logging.getLogger(__name__)


def get_config_param(param):
    return str(configuration.get('epantry', param))


class EpantryUser(models.User):

    def __init__(self, user):
        self.user = user

    def is_active(self):
        '''Required by flask_login'''
        return True

    def is_authenticated(self):
        '''Required by flask_login'''
        return True

    def is_anonymous(self):
        '''Required by flask_login'''
        return False

    def get_id(self):
        '''Returns the current user id as required by flask_login'''
        return self.user.get_id()

    def data_profiling(self):
        '''Provides access to data profiling tools'''
        return True

    def is_superuser(self):
        '''Access all the things'''
        return True


class AuthenticationError(Exception):
    pass


class EpantryAuthBackend(object):

    def __init__(self):
        self.login_manager = flask_login.LoginManager()
        self.login_manager.login_view = 'airflow.login'
        self.flask_app = None
        self.epantry_oauth = None

    def init_app(self, flask_app):
        self.flask_app = flask_app

        self.login_manager.init_app(self.flask_app)

        self.epantry_oauth = OAuth(self.flask_app).remote_app(
            'epantry',
            consumer_key=get_config_param('oauth_id'),
            consumer_secret=get_config_param('oauth_secret'),
            request_token_params={'scope': 'read'},
            base_url='https://www.grove.co/api',
            access_token_url='https://www.grove.co/api/o/token/',
            authorize_url='https://www.grove.co/api/o/authorize/')

        self.login_manager.user_loader(self.load_user)

        self.flask_app.add_url_rule('/oauth/authorized',
                                    'oauth_authorized',
                                    self.oauth_authorized)


    def login(self, request):
        _log.debug('Logging in via ePantry')
        return self.epantry_oauth.authorize(callback=url_for('oauth_authorized', _external=True))

    def authorize_user(self, user):
        if 'is_staff' in user and user.get('is_staff') is True:
            return True
        else:
            return False

    @provide_session
    def load_user(self, userid, session=None):
        if not userid or userid == 'None':
            return None

        user = session.query(models.User).filter(
            models.User.id == int(userid)).first()
        return EpantryUser(user)

    @provide_session
    def oauth_authorized(self, session=None):
        _log.debug('ePantry OAuth callback called')

        resp = self.epantry_oauth.authorized_response()

        try:
            if resp is None:
                raise AuthenticationError(
                    'Null response from ePantry, denying access.'
                )

            epantry_token = {
                'access_token': resp['access_token']
            }
            epantry_user = self.epantry_oauth.get('api/customer/', token=epantry_token).data
            print epantry_user
            username = epantry_user.get('full_name')
            email = epantry_user.get('email')
            print epantry_user, email

            if not self.authorize_user(epantry_user):
                return redirect(url_for('airflow.noaccess'))
        except AuthenticationError:
            return redirect(url_for('airflow.noaccess'))

        user = session.query(models.User).filter(
            models.User.username == username).first()

        if not user:
            user = models.User(
                username=username,
                email=email,
                is_superuser=False)

        session.merge(user)
        session.commit()
        login_user(EpantryUser(user))
        session.commit()

        next_url = request.args.get('next') or url_for('admin.index')
        return redirect(next_url)

login_manager = EpantryAuthBackend()


def login(self, request):
    return login_manager.login(request)
