from django.core.management.base import BaseCommand, CommandError
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from dashboard.models import User, Domains
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import os, random, base64

class Command(BaseCommand):

  def add_arguments(self, parser):
    parser.add_argument('-d', '--domain', type=ascii)

  def handle(self, *args, **kwargs):
    new_domain_name = eval(kwargs['domain'])
    domain_dirname = '/kubepanel/yaml_templates/'+new_domain_name
    os.mkdir(domain_dirname)
    root = User.objects.filter(is_superuser=True)
    dkimkey = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
    dkim_privkey = dkimkey.private_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, crypto_serialization.NoEncryption()).decode()
    dkim_pubkey = dkimkey.public_key().public_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PublicFormat.SubjectPublicKeyInfo).decode().splitlines()
    dkim_pubkey.pop()
    dkim_pubkey.pop(0)
    dkim_txt = ''.join(dkim_pubkey)
    dkim_txt_record = "v=DKIM1; k=rsa; p="+dkim_txt+";"
    new_domain = Domains(owner=root[0], domain_name = new_domain_name, title = new_domain_name, dkim_privkey = dkim_privkey, dkim_pubkey = dkim_txt_record)
    new_domain.save()

    #RENDER DKIM CONFIGMAPS AND PRIVATE KEYS
    dkim_privkeys_dir = '/dkim-privkeys/'+new_domain_name
    os.mkdir('/dkim-privkeys/'+new_domain_name)
    domains = { "domains" : Domains.objects.all() }
    render_to_file = render_to_string('yaml_templates/dkim-keytable-configmap.yaml', domains)
    with open(domain_dirname+'/dkim-keytable-configmap.yaml', 'w') as static_file:
        static_file.write(render_to_file)
    render_to_file = render_to_string('yaml_templates/dkim-signingtable-configmap.yaml', domains)
    with open(domain_dirname+'/dkim-signingtable-configmap.yaml', 'w') as static_file:
        static_file.write(render_to_file)
    render_to_file = render_to_string('yaml_templates/dkim-job.yaml')
    with open(domain_dirname+'/dkim-job.yaml', 'w') as static_file:
        static_file.write(render_to_file)
    static_file = open(dkim_privkeys_dir+'/'+new_domain_name+'.key', 'w')
    static_file.write(dkim_privkey)
    static_file.close()
    #END
