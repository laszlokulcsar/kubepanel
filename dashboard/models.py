from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from .defaultconfigs import NGINX_DEFAULT_CONFIG

class Domains(models.Model):
    title = models.CharField(max_length=255)
    def __str__(self):
        return self.title

    def validate_not_empty(value):
      if value.strip() == "":
        raise ValidationError('This field cannot be an empty string.')

    domain_name = models.CharField(max_length=255, unique=True, blank=False, validators=[validate_not_empty])
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    scp_privkey = models.TextField(db_default="")
    scp_pubkey = models.TextField(db_default="")
    scp_port = models.IntegerField(db_default=30000, validators=[MinValueValidator(30000), MaxValueValidator(32767)])
    dkim_privkey = models.TextField(db_default="")
    dkim_pubkey = models.TextField(db_default="")
    mariadb_user = models.CharField(max_length=255, unique=True)
    mariadb_pass = models.CharField(max_length=255)
    status =  models.CharField(max_length=255)
    storage_size = models.IntegerField(db_default=1, validators=[MinValueValidator(1), MaxValueValidator(10000)])
    cpu_limit = models.IntegerField(db_default=500, validators=[MinValueValidator(100), MaxValueValidator(4000)])
    mem_limit = models.IntegerField(db_default=256, validators=[MinValueValidator(32), MaxValueValidator(4096)])
    nginx_config = models.TextField(default=NGINX_DEFAULT_CONFIG)

class Volumesnapshot(models.Model):
    def __str__(self):
        return self.snapshotname

    domain = models.ForeignKey(Domains, on_delete=models.CASCADE)
    snapshotname = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

