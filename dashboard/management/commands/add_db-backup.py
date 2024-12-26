from django.core.management.base import BaseCommand, CommandError
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from dashboard.models import User, Domains, DBBackup
import os, random, base64

class Command(BaseCommand):

  def add_arguments(self, parser):
    parser.add_argument('-bn', '--backupname', type=ascii)
    parser.add_argument('-d', '--domain', type=ascii)

  def handle(self, *args, **kwargs):
    backupname = eval(kwargs['backupname'])
    domain_name = eval(kwargs['domain'])
    domain = Domains.objects.filter(domain_name = domain_name)
    add_backup = DBBackup(domain=domain[0], backupname = backupname)
    add_backup.save()
