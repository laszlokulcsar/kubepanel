from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator


class Domains(models.Model):
    title = models.CharField(max_length=255)
    def __str__(self):
        return self.title

    domain_name = models.CharField(max_length=255, unique=True)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    scp_privkey = models.TextField(db_default="")
    scp_pubkey = models.TextField(db_default="")
    scp_port = models.IntegerField(db_default=30000, validators=[MinValueValidator(30000), MaxValueValidator(32767)])
    dkim_privkey = models.TextField(db_default="")
    dkim_pubkey = models.TextField(db_default="")
    mariadb_user = models.CharField(max_length=255, unique=True)
    mariadb_pass = models.CharField(max_length=255)
    status =  models.CharField(max_length=255)

class Volumesnapshot(models.Model):
    def __str__(self):
        return self.snapshotname

    domain = models.ForeignKey(Domains, on_delete=models.PROTECT)
    snapshotname = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

