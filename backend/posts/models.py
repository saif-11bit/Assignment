from django.db import models
from authentication.models import User

# Create your models here.
class Post(models.Model):

    title = models.CharField(max_length=200)
    desc = models.TextField()
    by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.title}"