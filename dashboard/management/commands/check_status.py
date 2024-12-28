from django.core.management.base import BaseCommand, CommandError
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from dashboard.models import User, Domains, Volumesnapshot
import os, random, base64, requests

class Command(BaseCommand):

#  def add_arguments(self, parser):
#    parser.add_argument('-sn', '--snapshotname', type=ascii)
#    parser.add_argument('-d', '--domain', type=ascii)

  def handle(self, *args, **kwargs):
    domains = Domains.objects.all()
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    with open(token_path, 'r') as f:
      token = f.read().strip()
    headers = {
      "Authorization": f"Bearer {token}"
    }
    for domain in domains:
      namespace = domain.domain_name.replace(".","-") 
      url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods"
      response = requests.get(url, headers=headers, verify=ca_cert_path)
      response.raise_for_status()
      pods_data = response.json()
      if not (pods_data.get("items",[])):
        domain.status = "Not running"
        domain.save()
      domain.status = ""
      for item in pods_data.get("items", []):
        domain.status = domain.status + item['spec']['nodeName'] + "<br>" + item['metadata']['labels']['app'] + ":" + item['metadata']['annotations']['kubepanel.status'] + ", " + item['status']['phase'] + "<br>"
        domain.save()
