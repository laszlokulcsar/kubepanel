from django.contrib import admin
from .models import MailUser, ClusterIP, Domain, Volumesnapshot, BlockRule, DNSRecord, DNSZone, CloudflareAPIToken

admin.site.register(Domain)
admin.site.register(Volumesnapshot)
admin.site.register(BlockRule)
admin.site.register(DNSRecord)
admin.site.register(DNSZone)
admin.site.register(CloudflareAPIToken)
admin.site.register(ClusterIP)
admin.site.register(MailUser)
