import os
import hmac
import webapp2
import jinja2

from users import User


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):
    SECRET = "squeaker"

    def hash_str(self, s):
        return hmac.new(self.SECRET, s).hexdigest()

    def make_secure_val(self, s):
        return "%s|%s" % (s, hmac.new(self.SECRET, s).hexdigest())

    def check_secure_val(self, h):
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val

    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_template(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render_str(self, template, **params):
        params['user'] = self.user
        if self.user:
            params['display_user'] = self.user.username
            params['logged_in'] = True
        else:
            params['display_user'] = 'Visitor'
            params['logged_in'] = False
        return self.render_template(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def read_user(self):
        if self.user:
            user = self.user.username

        return user
