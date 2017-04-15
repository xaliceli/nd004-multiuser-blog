import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = "squeaker"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        if self.user:
            params['display_user'] = self.user.username
            params['logged_in'] = True
        else:
            params['display_user'] = 'Visitor'
            params['logged_in'] = False
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

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
        else:
            user = None

        return user


class MainPage(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie',
                                         'visits=%s' % new_cookie_val)

        if visits > 10000:
            self.write("You are the best ever!")
        else:
            self.write("You've been here %s times!" % visits)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    username = db.StringProperty(required=True)
    hashed_password = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('username = ', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    username=name,
                    hashed_password=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.hashed_password):
            return u


class BlogSignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        elif User.by_name(username):
            params['error_username'] = "That user already exists."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Passwords do not match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            new_user = User.register(name=username,
                                     pw=password,
                                     email=email)
            new_user.put()

            self.login(new_user)
            self.redirect('/blog')


class BlogLogin(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        params = dict(username=username)
        user = User.login(username, password)

        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            params['error_login'] = "Invalid login."
            self.render('login.html', **params)


class BlogLogout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class BlogWelcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.username)
        else:
            self.redirect('/signup')


def blog_key(name="default"):
    return db.Key.from_path("blogs", name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    date = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty()
    liked_by = db.StringListProperty()
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        return render_str("post.html", post=self)


class PostComment(db.Model):
    post = db.StringProperty(required=True)
    comment_author = db.StringProperty(required=True)
    comment_content = db.TextProperty(required=True)
    comment_date = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment_content.replace("\n", "<br>")
        return render_str("comment.html", comment=self)


class BlogHome(Handler):
    def render_front(self):
        posts = Post.all().order("-date")
        self.render("blog.html", posts=posts)

    def get(self):
        self.render_front()


class BlogPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = PostComment.all().order("-comment_date")
        self.render("permalink.html", post=post, comments=comments)

    def post(self, post_id):
        comment = self.request.get("comment")

        active_user = self.read_user()

        if comment and active_user:
            new_comment = PostComment(parent=blog_key(),
                                      post=post_id,
                                      comment_author=active_user,
                                      comment_content=comment)

            new_comment.put()
            self.redirect("/blog/%s/#comments" % str(post_id))
        else:
            self.render("permission_error.html")


class BlogNew(Handler):
    def render_post(self, error=""):
        self.render("newpost.html", error=error)

    def get(self):
        self.render_post()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        author = self.user.username

        if subject and content:
            new_post = Post(parent=blog_key(),
                            subject=subject,
                            author=author,
                            content=content,
                            likes=0,
                            liked_by=[])
            new_post.put()
            self.redirect("/blog/%s/" % str(new_post.key().id()))

        else:
            error = "Subject and content, please!"
            self.render_post(error=error)


class PostEdit(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        active_user = self.read_user()

        if active_user:
            if active_user == post.author:
                self.render("editpost.html", post=post)
            else:
                self.render("permission_error.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        subject = self.request.get("subject")
        content = self.request.get("content")

        post.subject = subject
        post.content = content

        post.put()
        self.redirect("/blog/%s/" % str(post.key().id()))


class PostDelete(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        active_user = self.read_user()

        if active_user:
            if active_user == post.author:
                post.delete()
                self.redirect('/blog/')
            else:
                self.render("permission_error.html")
        else:
            self.redirect("/login")


class PostLike(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        active_user = self.read_user()

        if active_user:
            if active_user != post.author and active_user not in post.liked_by:
                post.likes += 1
                post.liked_by.append(active_user)
                post.put()
                self.redirect("/blog/")
            else:
                self.render("permission_error.html")
        else:
            self.redirect("/login")


class PostUnlike(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        active_user = self.read_user()

        if active_user:
            if active_user != post.author and active_user in post.liked_by:
                post.likes -= 1
                post.liked_by.remove(active_user)
                post.put()
                self.redirect("/blog/")
            else:
                self.render("permission_error.html")
        else:
            self.redirect("/login")


class CommentEdit(Handler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path("PostComment", int(comment_id),
                               parent=blog_key())
        comment = db.get(key)

        active_user = self.read_user()

        if active_user:
            if active_user == comment.comment_author:
                self.render("editcomment.html", comment=comment)
            else:
                self.render("permission_error.html")
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        key = db.Key.from_path("PostComment", int(comment_id),
                               parent=blog_key())
        comment = db.get(key)

        comment_content = self.request.get("comment_content")
        comment.comment_content = comment_content
        comment.put()

        self.redirect("/blog/%s/" % str(post_id))


class CommentDelete(Handler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path("PostComment", int(comment_id),
                               parent=blog_key())
        comment = db.get(key)

        active_user = self.read_user()

        if active_user == comment.comment_author:
            comment.delete()
            self.redirect("/blog/%s/" % str(post_id))
        else:
            self.render("permission_error.html")


app = webapp2.WSGIApplication([('/', BlogWelcome),
                               ('/signup', BlogSignUp),
                               ('/welcome', BlogWelcome),
                               ('/login', BlogLogin),
                               ('/logout', BlogLogout),
                               ('/blog/?', BlogHome),
                               ('/blog/newpost', BlogNew),
                               ('/blog/([0-9]+)/?', BlogPost),
                               ('/blog/([0-9]+)/edit', PostEdit),
                               ('/blog/([0-9]+)/delete', PostDelete),
                               ('/blog/([0-9]+)/like', PostLike),
                               ('/blog/([0-9]+)/unlike', PostUnlike),
                               ('/blog/([0-9]+)/([0-9]+)/edit', CommentEdit),
                               ('/blog/([0-9]+)/([0-9]+)/delete', CommentDelete)],
                              debug=True)
