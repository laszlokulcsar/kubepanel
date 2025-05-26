from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from .defaultconfigs import NGINX_DEFAULT_CONFIG
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db.models.signals import post_save
from django.dispatch import receiver

def validate_not_empty(value):
    if isinstance(value, str) and value.strip() == "":
        raise ValidationError('This field cannot be an empty string.')

class Package(models.Model):
    name = models.CharField(max_length=255, unique=True)
    max_storage_size = models.IntegerField(default=1, validators=[MinValueValidator(1), MaxValueValidator(10000)])
    max_cpu = models.IntegerField(default=500, validators=[MinValueValidator(100), MaxValueValidator(4000)])
    max_memory = models.IntegerField(default=256, validators=[MinValueValidator(32), MaxValueValidator(4096)])
    max_mail_users = models.IntegerField(null=True, blank=True)
    max_mail_aliases = models.IntegerField(null=True, blank=True)
    max_domain_aliases = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    package = models.ForeignKey(Package, on_delete=models.PROTECT, null=True, blank=True)

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class Domain(models.Model):
    title = models.CharField(max_length=255)
    def __str__(self):
        return self.title
    domain_name = models.CharField(max_length=255, unique=True, validators=[validate_not_empty])
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    scp_privkey = models.TextField(db_default="")
    scp_pubkey = models.TextField(db_default="")
    scp_port = models.IntegerField(db_default=30000, validators=[MinValueValidator(30000), MaxValueValidator(32767)])
    dkim_privkey = models.TextField(db_default="")
    dkim_pubkey = models.TextField(db_default="")
    mariadb_user = models.CharField(max_length=255, unique=True)
    mariadb_pass = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    storage_size = models.IntegerField(db_default=1, validators=[MinValueValidator(1), MaxValueValidator(10000)])
    cpu_limit = models.IntegerField(db_default=500, validators=[MinValueValidator(100), MaxValueValidator(4000)])
    mem_limit = models.IntegerField(db_default=256, validators=[MinValueValidator(32), MaxValueValidator(4096)])
    nginx_config = models.TextField(default=NGINX_DEFAULT_CONFIG)

    def clean(self):
        super().clean()
        pkg = self.owner.profile.package
        domains = Domain.objects.filter(owner=self.owner)
        if self.pk:
            domains = domains.exclude(pk=self.pk)
        total_storage = sum(d.storage_size for d in domains) + self.storage_size
        if total_storage > pkg.max_storage_size:
            raise ValidationError({'storage_size': f"Total storage ({total_storage}) exceeds package limit ({pkg.max_storage_size})."})
        total_cpu = sum(d.cpu_limit for d in domains) + self.cpu_limit
        if total_cpu > pkg.max_cpu:
            raise ValidationError({'cpu_limit': f"Total CPU ({total_cpu}) exceeds package limit ({pkg.max_cpu})."})
        total_mem = sum(d.mem_limit for d in domains) + self.mem_limit
        if total_mem > pkg.max_memory:
            raise ValidationError({'mem_limit': f"Total memory ({total_mem}) exceeds package limit ({pkg.max_memory})."})
        if pkg.max_domain_aliases is not None:
            existing_aliases = sum(d.aliases.count() for d in domains)
            # only count self.aliases on updates
            new_aliases = self.aliases.count() if self.pk else 0
            total_aliases = existing_aliases + new_aliases
            if total_aliases > pkg.max_domain_aliases:
                raise ValidationError({
                    'aliases': (
                        f"Total domain aliases ({total_aliases}) exceed "
                        f"package limit ({pkg.max_domain_aliases})."
                    )
                })
        if pkg.max_mail_users is not None:
            from .models import MailUser
            total_mail_users = MailUser.objects.filter(domain__owner=self.owner).count()
            if total_mail_users > pkg.max_mail_users:
                raise ValidationError({'mail_users': f"Total mail users ({total_mail_users}) exceed package limit ({pkg.max_mail_users})."})

    @property
    def all_hostnames(self):
        names = [self.domain_name]
        names += [alias.alias_name for alias in self.aliases.all()]
        return names

    @property
    def server_name_directive(self):
        return " ".join(self.all_hostnames)

# alias for migrations compatibility
Domain.validate_not_empty = validate_not_empty

class DomainAlias(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='aliases')
    alias_name = models.CharField(max_length=255, unique=True, validators=[validate_not_empty])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Domain Alias"
        verbose_name_plural = "Domain Aliases"
        ordering = ['domain__domain_name', 'alias_name']

    def __str__(self):
        return f"{self.alias_name} → {self.domain.domain_name}"

class Volumesnapshot(models.Model):
    def __str__(self):
        return self.snapshotname

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    snapshotname = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    log = models.TextField(db_default="")

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

class MailUser(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='mail_users')
    local_part = models.CharField(max_length=64)  # e.g. "info"
    password = models.CharField(max_length=255)   # store hashed value
    active = models.BooleanField(default=True)

    @property
    def email(self):
        return f"{self.local_part}@{self.domain.domain_name}"

    @property
    def aliases(self):
        # return all active MailAlias objects that forward *to* this mailbox
        return MailAlias.objects.filter(
            destination__iexact=self.email,
            active=True
        )

    def __str__(self):
        return self.email

class MailAlias(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='mail_aliases')
    source = models.CharField(max_length=255)      # e.g. "alias@example.com"
    destination = models.CharField(max_length=255) # e.g. "real@example.com"
    active = models.BooleanField(default=True)

class LogEntry(models.Model):
    LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]

    timestamp      = models.DateTimeField(auto_now_add=True)
    content_type   = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name='dashboard_log_entries'
    )
    object_id      = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    actor = models.CharField(
        max_length=100,
        help_text="Identifier of the actor (e.g. 'user:alice', 'backup_cron')"
    )
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='dashboard_user_log_entries',
        help_text="Optional link to the authenticated user"
    )

    level   = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='INFO')
    message = models.TextField()
    data    = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return (
            f"[{self.level}] {self.timestamp:%Y-%m-%d %H:%M:%S} "
            f"— {self.actor} → {self.content_object}: {self.message}"
        )

