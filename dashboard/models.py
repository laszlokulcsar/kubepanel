from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from .defaultconfigs import NGINX_DEFAULT_CONFIG

class Domain(models.Model):
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

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    snapshotname = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

class BlockRule(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    
    ip_address = models.CharField(max_length=45, blank=True, null=True)
    vhost = models.CharField(max_length=255, blank=True, null=True)
    path = models.CharField(max_length=2000, blank=True, null=True)
    
    block_ip = models.BooleanField(default=False)
    block_vhost = models.BooleanField(default=False)
    block_path = models.BooleanField(default=False)

    def __str__(self):
        return f"BlockRule {self.pk} [IP={self.ip_address}, vhost={self.vhost}, path={self.path}]"

class CloudflareAPIToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    api_token = models.TextField()

    def __str__(self):
        return f"{self.user.username} - {self.name}"

class DNSZone(models.Model):
    name = models.CharField(max_length=253)
    zone_id = models.CharField(max_length=64)
    token = models.ForeignKey(CloudflareAPIToken, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.zone_id})"

class DNSRecord(models.Model):
    RECORD_TYPES = [
        ("A", "A"),
        ("AAAA", "AAAA"),
        ("CNAME", "CNAME"),
        ("TXT", "TXT"),
        ("MX", "MX"),
        ("NS", "NS"),
        ("SRV", "SRV"),
    ]

    zone = models.ForeignKey("DNSZone", on_delete=models.CASCADE, related_name="dns_records")
    record_type = models.CharField(max_length=10, choices=RECORD_TYPES)
    name = models.CharField(max_length=253)
    content = models.TextField(db_default="")
    ttl = models.IntegerField(default=120)
    proxied = models.BooleanField(default=False)
    priority = models.IntegerField(null=True, blank=True)
    cf_record_id = models.CharField(max_length=64, null=True, blank=True)

    def __str__(self):
        return f"{self.record_type} {self.name} -> {self.content}"

class ClusterIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.ip_address} ({self.description or 'No Description'})"

