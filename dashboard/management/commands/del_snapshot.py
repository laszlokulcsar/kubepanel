from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
from dashboard.models import Domain, Volumesnapshot

class Command(BaseCommand):
    help = "Delete VolumeSnapshot entries older than a specified number of days for a given domain"

    def add_arguments(self, parser):
        parser.add_argument(
            '-d', '--days',
            type=int,
            default=6,
            help="Delete snapshots older than this many days"
        )
        parser.add_argument(
            '-dn', '--domain',
            type=ascii,
            required=True,
            help="Domain name whose snapshots should be cleaned up"
        )

    def handle(self, *args, **options):
        days = options['days']
        domain_name = eval(options['domain'])

        try:
            domain = Domain.objects.get(domain_name=domain_name)
        except Domain.DoesNotExist:
            raise CommandError(f"Domain \u201c{domain_name}\u201d not found")

        cutoff = timezone.now() - timedelta(days=days)
        old_qs = Volumesnapshot.objects.filter(
            domain=domain,
            created__lt=cutoff
        )

        count = old_qs.count()
        old_qs.delete()

        self.stdout.write(self.style.SUCCESS(
            f"Deleted {count} snapshots for domain '{domain_name}' older than {days} days"
        ))

