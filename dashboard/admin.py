from django.contrib import admin
from .models import LogEntry, MailUser, MailAlias, ClusterIP, Domain, DomainAlias, Volumesnapshot, BlockRule, DNSRecord, DNSZone, CloudflareAPIToken

admin.site.register(Domain)
admin.site.register(DomainAlias)
admin.site.register(Volumesnapshot)
admin.site.register(BlockRule)
admin.site.register(DNSRecord)
admin.site.register(DNSZone)
admin.site.register(CloudflareAPIToken)
admin.site.register(ClusterIP)
admin.site.register(MailUser)
admin.site.register(MailAlias)
admin.site.register(LogEntry)
