from django.core.management.base import BaseCommand, CommandError
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from dashboard.models import User, Domain, Volumesnapshot
import os, random, base64

class Command(BaseCommand):
    help = "Register a new VolumeSnapshot and (optionally) record its log file"

    def add_arguments(self, parser):
        parser.add_argument('-sn', '--snapshotname', type=ascii, required=True)
        parser.add_argument('-d',  '--domain',       type=ascii, required=True)
        parser.add_argument('-f',  '--logfile',      type=str,
                            help="Path to a file containing the full backup log")

    def handle(self, *args, **kwargs):
        snapshotname = eval(kwargs['snapshotname'])
        domain_name   = eval(kwargs['domain'])
        logfile       = kwargs.get('logfile')

        try:
            domain = Domain.objects.get(domain_name=domain_name)
        except Domain.DoesNotExist:
            raise CommandError(f"Domain “{domain_name}” not found")

        # Read the logfile (if given)
        logs = ''
        if logfile:
            if not os.path.exists(logfile):
                raise CommandError(f"logfile “{logfile}” does not exist")
            with open(logfile, 'r') as f:
                logs = f.read()

        vs = Volumesnapshot(
            domain       = domain,
            snapshotname = snapshotname,
            log          = logs
        )
        vs.save()
        self.stdout.write(self.style.SUCCESS(
            f"Saved snapshot {snapshotname} ({len(logs)} bytes of logs)"
        ))
