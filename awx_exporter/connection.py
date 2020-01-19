import requests


# mostly copied from awxkit
class Token_Auth(requests.auth.AuthBase):
    def __init__(self, token, auth_type='Token'):
        self.token = token
        self.auth_type = auth_type

    def __call__(self, request):
        request.headers['Authorization'] = '{0.auth_type} {0.token}'.format(self)
        return request


class Connection(object):
    def __init__(self, server, verify=False, max_connection_attempts: int = 5):
        self.server = server
        self.verify = verify
        self.MAX_CONNECTION_ATTEMPTS = max_connection_attempts
        if not self.verify:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.uses_session_cookie = False

    def get_session_requirements(self, next='/api/'):
        self.get('/api/')  # this causes a cookie w/ the CSRF token to be set
        return dict(next=next)

    def login(self, username=None, password=None, token=None, **kwargs):
        if username and password:
            _next = kwargs.get('next')
            if _next:
                headers = self.session.headers.copy()
                self.post('/api/login/', headers=headers,
                          data=dict(username=username, password=password, next=_next))
                self.session_id = self.session.cookies.get('sessionid')
                self.uses_session_cookie = True
            else:
                self.session.auth = (username, password)
        elif token:
            self.session.auth = Token_Auth(token, auth_type=kwargs.get('auth_type', 'Token'))
        else:
            self.session.auth = None

    def logout(self):
        if self.uses_session_cookie:
            self.session.cookies.pop('sessionid', None)
        else:
            self.session.auth = None

    def request(self, relative_endpoint, method='get', json=None, data=None, query_parameters=None, headers=None):
        """Core requests.Session wrapper that returns requests.Response objects"""
        session_request_method = getattr(self.session, method, None)
        if not session_request_method:
            raise Exception("Unknown request method: {0}".format(method))

        use_endpoint = relative_endpoint
        if self.server.endswith('/'):
            self.server = self.server[:-1]
        if use_endpoint.startswith('/'):
            use_endpoint = use_endpoint[1:]
        url = '/'.join([self.server, use_endpoint])

        kwargs = dict(verify=self.verify, params=query_parameters, json=json, data=data
                      )

        if headers is not None:
            kwargs['headers'] = headers

        if method in ('post', 'put', 'patch', 'delete'):
            kwargs.setdefault('headers', {})['X-CSRFToken'] = self.session.cookies.get('csrftoken')
            kwargs['headers']['Referer'] = url

        for attempt in range(1, self.MAX_CONNECTION_ATTEMPTS + 1):
            try:
                response = session_request_method(url, **kwargs)
                break
            except requests.exceptions.ConnectionError as err:
                if attempt == self.MAX_CONNECTION_ATTEMPTS:
                    raise err
                print('Failed to reach url: {0}.  Retrying.'.format(url))

        return response

    def get(self, relative_endpoint, query_parameters=None, headers=None):
        return self.request(relative_endpoint, method='get', query_parameters=query_parameters, headers=headers)

    def post(self, relative_endpoint, json=None, data=None, headers=None):
        return self.request(relative_endpoint, method='post', json=json, data=data, headers=headers)
