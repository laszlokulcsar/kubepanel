from django.contrib import admin
from .models import Domain, Volumesnapshot, BlockRule, DNSRecord, CloudflareAPIToken

admin.site.register(Domain)
admin.site.register(Volumesnapshot)
admin.site.register(BlockRule)
admin.site.register(DNSRecord)
admin.site.register(CloudflareAPIToken)
