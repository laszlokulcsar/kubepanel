from django.contrib import admin
from .models import Domains, Volumesnapshot, BlockRule

admin.site.register(Domains)
admin.site.register(Volumesnapshot)
admin.site.register(BlockRule)
