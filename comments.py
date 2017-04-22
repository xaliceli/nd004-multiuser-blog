from google.appengine.ext import db
from handlers import Handler


class PostComment(db.Model, Handler):
    post = db.StringProperty(required=True)
    comment_author = db.StringProperty(required=True)
    comment_content = db.TextProperty(required=True)
    comment_date = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment_content.replace("\n", "<br>")
        return self.render_template("comment.html", comment=self)
