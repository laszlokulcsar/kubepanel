from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import User, Domains, Volumesnapshot
from django.urls import reverse
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

import os, random, base64, string, requests

TEMPLATE_BASE = "/kubepanel/dashboard/templates/"

def kplogin(request):
    try:
        username = request.POST["username"][:20]
        password = request.POST["password"][:40]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect(kpmain)
        else:
            return HttpResponse("Invalid login")
    except:
        return render(request, "login/login.html")

@login_required(login_url="/dashboard/")
def kpmain(request):
    domains = { "domains" : Domains.objects.filter(owner=request.user) }
    return render(request, "main/domain.html", domains)

@login_required(login_url="/dashboard/")
def volumesnapshots(request,domain):
    domain_obj = Domains.objects.get(domain_name=domain)
    context = {"volumesnapshots" : Volumesnapshot.objects.filter(domain=domain_obj), "domain" : domain }
    return render(request, "main/volumesnapshot.html", context)

def settings(request):
    return render(request, "main/settings.html")

def logout_view(request):
    logout(request)
    return render(request, "login/login.html")

def generate_scp_port():
    scp_port_taken = 1
    while(scp_port_taken):
      scp_port = random.randint(30000,32767)
      scp_port_taken = Domains.objects.filter(scp_port=scp_port)
    return scp_port

def random_string(num):
  char_set = string.ascii_lowercase + string.digits
  rndstring = ''.join(random.sample(char_set*6, num))
  return rndstring

def iterate_input_templates(template_dirname,domain_dirname,context):
    domain_dirname = domain_dirname
    context = context
    for root, _, files in os.walk(TEMPLATE_BASE+template_dirname):
        for file_name in files:
            if file_name.endswith(".yaml"):
              #file_path = os.path.relpath(os.path.join(root, file_name),template_dirname)
              render_yaml(domain_dirname,template_dirname+file_name,context,file_name)

def render_yaml(domain_dirname,input_filename,context,file_name):
  render_to_file = render_to_string(input_filename, context)
  with open(domain_dirname+'/'+file_name, 'w') as static_file:
      static_file.write(render_to_file)


@login_required(login_url="/dashboard/")
def add_domain(request):
    if request.method == 'POST':
        new_domain_name = request.POST["domain_name"][:60]
        if request.POST["wordpress_preinstall"] == 'on':
          wp_preinstall = True
        else:
          wp_preinstall = False

        #GENERATE SSH AND DKIM PRIV/PUB KEYS
        sshkey = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
        private_key = sshkey.private_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, crypto_serialization.NoEncryption()).decode("utf-8")
        public_key = sshkey.public_key().public_bytes(crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH).decode("utf-8")
        dkimkey = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
        dkim_privkey = dkimkey.private_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, crypto_serialization.NoEncryption()).decode()
        dkim_pubkey = dkimkey.public_key().public_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PublicFormat.SubjectPublicKeyInfo).decode().splitlines()
        dkim_pubkey.pop()
        dkim_pubkey.pop(0)
        dkim_txt = ''.join(dkim_pubkey)
        dkim_txt_record = "v=DKIM1; k=rsa; p="+dkim_txt+";"
        #END
        
        scp_port = generate_scp_port()
        mariadb_pass = random_string(12)
        jobid = random_string(5)
        mariadb_user = new_domain_name.replace(".","_")
        status = "Startup in progress"
        new_domain = Domains(owner=request.user, domain_name = new_domain_name, title = new_domain_name, scp_privkey = private_key, scp_pubkey = public_key, scp_port = scp_port, dkim_privkey = dkim_privkey, dkim_pubkey = dkim_txt_record, mariadb_pass = mariadb_pass, mariadb_user = mariadb_user, status = status)
        domain_dirname = '/kubepanel/yaml_templates/'+new_domain_name
        context = { "domains" : Domains.objects.all(), "jobid" : jobid, "domain_name_dash" : new_domain.domain_name.replace(".","-"), "domain_name_underscore" : new_domain.domain_name.replace(".","_"), "domain_name" : new_domain.domain_name, "public_key" : public_key, "scp_port" : scp_port, "dkim_privkey" : dkim_privkey, "mariadb_pass" : mariadb_pass, "mariadb_user" : mariadb_user, "wp_preinstall" : wp_preinstall}
        try:
          new_domain.save()
        except:
          print("Ooops, can't save domain, please check debug logs.")
          return render(request, "main/domain_error.html",{ "domain" : new_domain_name,})
        try:
          os.mkdir(domain_dirname)
          os.mkdir('/dkim-privkeys/'+new_domain_name)
        except:
          print("Can't create directories. Please check debug logs if you think this is an error.")
        template_dir = "yaml_templates/"
        iterate_input_templates(template_dir,domain_dirname,context)
	
	#RENDER DKIM PRIVATE KEYS
        dkim_privkeys_dir = '/dkim-privkeys/'+new_domain_name
        static_file = open(dkim_privkeys_dir+'/'+new_domain_name+'.key', 'w')
        static_file.write(dkim_privkey)
        static_file.close()
        #END

        return redirect(kpmain)
    else:
        return render(request, "main/add_domain.html")
    return True

@login_required(login_url="/dashboard/")
def pause_domain(request,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
          permission_valid = Domains.objects.get(owner=request.user, domain_name = domain)
        except:
          return HttpResponse("Permission denied.")
        if permission_valid:
          host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
          port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
          namespace = domain.replace(".","-")
          token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
          ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
          with open(token_path, 'r') as f:
            token = f.read().strip()
          headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": f"application/strategic-merge-patch+json"
          }
          payload = {
 	   "spec": {
             "replicas": "0"
            }
          }
          url = f"https://{host}:{port}/apis/apps/v1/namespaces/{namespace}/deployments/nginx"
          try:
              response = requests.patch(url, headers=headers, data=json.dumps(payload), verify=False)  # Disable SSL verification for simplicity
              if response.status_code == 200:
                  print(f"Deployment nginx successfully scaled to 0 replicas.")
              else:
                  print(f"Failed to scale deployment. Status Code: {response.status_code}")
                  print(f"Response: {response.text}")
          except requests.exceptions.RequestException as e:
              print(f"Error while scaling deployment: {e}")
      else:
        error = "Domain name didn't match"
        return render(request, "main/pause_domain.html", { "domain" : domain, "error" : error})
    else:
      return render(request, "main/pause_domain.html", { "domain" : domain})  
    return redirect(kpmain)

@login_required(login_url="/dashboard/")
def restore_volumesnapshot(request,volumesnapshot,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
          permission_valid = Domains.objects.get(owner=request.user, domain_name = domain)
        except:
          return HttpResponse("Permission denied.")
        if permission_valid:
          template_dir = "restore_templates/"
          domain_dirname = '/kubepanel/yaml_templates/'+domain
          try:
            os.mkdir(domain_dirname)
            os.mkdir('/dkim-privkeys/'+domain)
          except:
            print("Can't create directories. Please check debug logs if you think this is an error.")
          jobid = random_string(5)
          context = { "jobid" : jobid, "domain_name_underscore" : domain.replace(".","_"), "domain_name_dash" : domain.replace(".","-"), "volumesnapshot" : volumesnapshot }
          iterate_input_templates(template_dir,domain_dirname,context)
      else:
        error = "Domain name didn't match"
        return render(request, "main/restore_snapshot.html", { "volumesnapshot" : volumesnapshot, "domain" : domain, "error" : error})
    else:
      return render(request, "main/restore_snapshot.html", { "volumesnapshot" : volumesnapshot, "domain" : domain})
    return redirect(kpmain)

@login_required(login_url="/dashboard/")
def delete_domain(request,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
            domain_to_delete = Domains.objects.get(owner=request.user, domain_name = domain)
        except:
            return HttpResponse("Permission denied.")
        if domain_to_delete:
            domain_to_delete.delete()
            domain_dirname = '/kubepanel/yaml_templates/'+domain
            try:
              os.mkdir(domain_dirname)
              os.mkdir('/dkim-privkeys/'+domain)
            except:
              print("Can't create directories. Please check debug logs if you think this is an error.")
            jobid = random_string(5)
            context = { "domains" : Domains.objects.all(), "jobid" : jobid, "domain_name_dash" : domain.replace(".","-"), "domain_name_underscore" : domain.replace(".","_")}
            template_dir = "delete_templates/"
            iterate_input_templates(template_dir,domain_dirname,context)
      else:
        error = "Domain name didn't match"
        return render(request, "main/delete_domain.html", { "domain" : domain, "error" : error})
    else:
      return render(request, "main/delete_domain.html", { "domain" : domain,})
    return redirect(kpmain)

@login_required(login_url="/dashboard/")
def view_domain(request,domain):
  try:
    domain = Domains.objects.get(owner=request.user, domain_name = domain)
    context = {"domain_name" : domain.domain_name, "sftp_privkey" : domain.scp_privkey, "db_user" : domain.mariadb_user, "db_pass" : domain.mariadb_pass, "sftp_port" : domain.scp_port, "dkim_pubkey" : domain.dkim_pubkey}
  except:
    return HttpResponse("Permission denied.")
  return render(request, "main/view_domain.html", { "domain" : domain})
