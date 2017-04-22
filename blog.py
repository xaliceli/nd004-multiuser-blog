import webapp2
from google.appengine.ext import db

import users
from posts import Post
from comments import PostComment
from handlers import Handler


def blog_key(name="default"):
    return db.Key.from_path("blogs", name)


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

        if not users.valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        elif users.User.by_name(username):
            params['error_username'] = "That user already exists."
            have_error = True

        if not users.valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Passwords do not match."
            have_error = True

        if not users.valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            new_user = users.User.register(name=username,
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
        user = users.User.login(username, password)

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
        active_user = self.read_user()

        if active_user:
            self.render_post()
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        author = self.user.username

        active_user = self.read_user()

        if active_user:
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
        else:
            self.redirect("/login")


class PostEdit(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
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

        active_user = self.read_user()

        if post:
            if active_user:
                if active_user == post.author:
                    subject = self.request.get("subject")
                    content = self.request.get("content")

                    post.subject = subject
                    post.content = content

                    post.put()
                    self.redirect("/blog/%s/" % post_id)
                else:
                    self.render("permission_error.html")
            else:
                self.redirect("/login")


class PostDel(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
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

        if post:
            active_user = self.read_user()

            if active_user:
                if (active_user != post.author and
                   active_user not in post.liked_by):
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

        active_user = self.read_user()

        if active_user:
            if active_user == comment.comment_author:
                comment_content = self.request.get("comment_content")
                comment.comment_content = comment_content
                comment.put()
                self.redirect("/blog/%s/" % str(post_id))
            else:
                self.render("permission_error.html")
        else:
            self.redirect("/login")


class CommentDel(Handler):
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
                               ('/blog/([0-9]+)/delete', PostDel),
                               ('/blog/([0-9]+)/like', PostLike),
                               ('/blog/([0-9]+)/unlike', PostUnlike),
                               ('/blog/([0-9]+)/([0-9]+)/edit', CommentEdit),
                               ('/blog/([0-9]+)/([0-9]+)/delete', CommentDel)],
                              debug=True)
