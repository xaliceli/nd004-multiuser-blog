from google.appengine.ext import db
from handlers import Handler


class Post(db.Model, Handler):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    date = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty()
    liked_by = db.StringListProperty()
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        return self.render_template("post.html", post=self)
