from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from .models import MailUser, ClusterIP, DNSZone, User, Domain, Volumesnapshot, BlockRule, DNSRecord, CloudflareAPIToken
from dashboard.forms import MailUserForm, DomainForm, DomainAddForm, APITokenForm, ZoneCreationForm, DNSRecordForm
from django.urls import reverse
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from datetime import datetime
from cloudflare import Cloudflare
from django.contrib import messages

import cloudflare, logging, os, random, base64, string, requests, json, geoip2.database

GEOIP_DB_PATH = "/kubepanel/GeoLite2-Country.mmdb"
TEMPLATE_BASE = "/kubepanel/dashboard/templates/"
EXCLUDED_EXTENSIONS = [".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"]

def manage_ips(request):
    ip_list = ClusterIP.objects.all()
    return render(request, "main/ip_management.html", {"ip_list": ip_list})

def add_ip(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        description = request.POST.get("description", "").strip()

        if not ip_address:
            messages.error(request, "IP address is required.")
            return redirect("manage_ips")

        try:
            ClusterIP.objects.create(ip_address=ip_address, description=description)
            messages.success(request, f"IP Address '{ip_address}' added successfully.")
        except Exception as e:
            messages.error(request, f"Error adding IP: {e}")

        return redirect("manage_ips")

# Delete an IP address
def delete_ip(request, ip_id):
    ip = get_object_or_404(ClusterIP, id=ip_id)
    if request.method == "POST":
        ip.delete()
        messages.success(request, f"IP Address '{ip.ip_address}' deleted successfully.")
        return redirect("manage_ips")

def delete_zone(request, zone_id):
    zone = get_object_or_404(DNSZone, id=zone_id, token__user=request.user)
    if request.method == "POST":
        try:
            # Optionally, add logic to delete the zone from Cloudflare
            zone.delete()
            messages.success(request, f"DNS Zone '{zone.name}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting zone: {e}")
        return redirect("zones_list")
    return render(request, "main/delete_confirm.html", {"object": zone, "type": "DNS Zone"})

def delete_dns_record(request, record_id):
    record = get_object_or_404(DNSRecord, id=record_id, zone__token__user=request.user)
    if request.method == "POST":
        try:
            record.delete()
            messages.success(request, f"DNS Record '{record.name}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting record: {e}")
        return redirect("list_dns_records", zone_id=record.zone.id)
    return render(request, "main/delete_confirm.html", {"object": record, "type": "DNS Record"})

# Delete a Cloudflare API Token
def delete_api_token(request, token_id):
    token = get_object_or_404(CloudflareAPIToken, id=token_id, user=request.user)
    if request.method == "POST":
        try:
            token.delete()
            messages.success(request, f"API Token '{token.name}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting token: {e}")
        return redirect("list_api_tokens")
    return render(request, "main/delete_confirm.html", {"object": token, "type": "API Token"})


def list_api_tokens(request):
    tokens = CloudflareAPIToken.objects.filter(user=request.user)
    return render(request, "main/list_api_tokens.html", {"tokens": tokens})

def list_dns_records(request, zone_id):
    zone = get_object_or_404(DNSZone, pk=zone_id)
    # Get DNS records from your local database rather than pulling from Cloudflare
    records = zone.dns_records.all()
    
    return render(request, "main/list_dns_records.html", {"zone": zone, "records": records})

def create_dns_record_in_cloudflare(record_obj):
    """
    Creates a DNS record in Cloudflare based on the DNSRecord instance (record_obj).
    Returns the Cloudflare response object on success, or raises an exception on failure.
    """
    client = Cloudflare(api_token=record_obj.zone.token.api_token)
    response = client.dns.records.create(
        zone_id=record_obj.zone.zone_id,
        type=record_obj.record_type,
        name=record_obj.name,
        content=record_obj.content,
        ttl=record_obj.ttl,
        proxied=record_obj.proxied
    )
    return response

def create_dns_record(request):
    if request.method == "POST":
        form = DNSRecordForm(request.POST, user=request.user)
        if form.is_valid():
            record_obj = form.save(commit=False)
            try:
                response = create_dns_record_in_cloudflare(record_obj)
                record_obj.cf_record_id = response.id
                record_obj.save()
                messages.success(request, "DNS record created successfully.")
            except Exception as e:
                messages.error(request, f"Error creating DNS record: {e}")
            return redirect("/zones/list")
        else:
            messages.error(request, "Form invalid.")
    else:
        form = DNSRecordForm(user=request.user)
    return render(request, "main/create_dns_record.html", {"form": form})


def zones_list(request):
    tokens = CloudflareAPIToken.objects.filter(user=request.user)
    user_zones = DNSZone.objects.filter(token__in=tokens)
    return render(request, "main/zones_list.html", {"zones": user_zones})

def add_api_token(request):
    if request.method == "POST":
        form = APITokenForm(request.POST)
        if form.is_valid():
            token_obj = form.save(commit=False)
            token_obj.user = request.user
            token_obj.save()
            return redirect("list_api_tokens")
    else:
        form = APITokenForm()
    return render(request, "main/add_token.html", {"form": form})

def create_cf_zone(zone_name, token):
    """
    Creates a zone in Cloudflare using the given token.
    Returns the newly created zone ID on success.
    Raises an exception on error.
    """
    client = Cloudflare(api_token=token.api_token)
    accounts = client.accounts.list().result

    if not accounts:
        raise ValueError("No accounts found for this token.")

    account_id = accounts[0].id
    result = client.zones.create(
        account={"id": account_id},
        name=zone_name,
        type="full",
    )
    return result.id

def create_zone(request):
    if request.method == "POST":
        form = ZoneCreationForm(request.user, request.POST)
        if form.is_valid():
            zone_name = form.cleaned_data["zone_name"]
            user_token = form.cleaned_data["token"]
            try:
                zone_id = create_cf_zone(zone_name, user_token)
                DNSZone.objects.create(
                    name=zone_name,
                    zone_id=zone_id,
                    token=user_token
                )
                messages.success(request, f"Zone '{zone_name}' created successfully.")
            except Exception as e:
                messages.error(request, f"Error creating zone: {str(e)}")
            return redirect("zones_list")
    else:
        form = ZoneCreationForm(request.user)
    return render(request, "main/create_zone.html", {"form": form})

@login_required(login_url="/dashboard/")
def blocked_objects(request):
    all_blocks = BlockRule.objects.all().order_by('-created_at')

    paginator = Paginator(all_blocks, 100)  # Adjust the number of items per page as needed
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST' and 'generate_rules' in request.POST:
        rules = render_modsec_rules()
        template_dir = "fw_templates/"
        jobid = random_string(5)
        context = { "rules" : rules, "jobid" : jobid }
        domain_dirname = '/kubepanel/yaml_templates/fwrules'
        try:
          os.mkdir(domain_dirname)
        except:
          print("Can't create directories. Please check debug logs if you think this is an error.")
        iterate_input_templates(template_dir,domain_dirname,context)
        return render(request, 'main/in_progress.html')

    return render(request, 'main/blocked_objects.html', {'page_obj': page_obj})

@login_required(login_url="/dashboard/")
def block_entry(request, vhost, x_forwarded_for, path):
    if request.method == 'POST':
        block_ip = bool(request.POST.get('block_ip'))
        block_vhost = bool(request.POST.get('block_vhost'))
        block_path = bool(request.POST.get('block_path'))

        # Save a new BlockRule row
        BlockRule.objects.create(
            ip_address = x_forwarded_for if block_ip else None,
            vhost = vhost if block_vhost else None,
            path = path if block_path else None,
            block_ip = block_ip,
            block_vhost = block_vhost,
            block_path = block_path
        )
        return render(request, 'main/in_progress.html')
    else:
        context = {
            'vhost': vhost,
            'x_forwarded_for': x_forwarded_for,
            'path': path
        }
        return render(request, 'main/block_entry.html', context)

def generate_modsec_rule(br: BlockRule) -> str:
    conditions = []
    if br.block_ip and br.ip_address:
        conditions.append(("REMOTE_ADDR", br.ip_address))
    if br.block_vhost and br.vhost:
        conditions.append(("SERVER_NAME", br.vhost))
    if br.block_path and br.path:
        conditions.append(("REQUEST_URI", br.path))

    if not conditions:
        return ""

    rule_id = 10000 + br.pk  
    msg_parts = []

    if br.block_ip:
        msg_parts.append("IP")
    if br.block_vhost:
        msg_parts.append("vhost")
    if br.block_path:
        msg_parts.append("path")
    msg_string = f"Blocking {', '.join(msg_parts)}"

    if len(conditions) == 1:
        var, val = conditions[0]
        return (
            f'SecRule {var} "@streq {val}" '
            f'"phase:1,id:{rule_id},deny,msg:\'{msg_string}\'"'
        )

    rule_lines = []
    
    first_var, first_val = conditions[0]
    rule_lines.append(
        f'SecRule {first_var} "@streq {first_val}" '
        f'"phase:1,id:{rule_id},deny,chain,msg:\'{msg_string}\'"'
    )

    for var, val in conditions[1:-1]:
        rule_lines.append(f'    SecRule {var} "@streq {val}" "chain"')

    last_var, last_val = conditions[-1]
    rule_lines.append(f'    SecRule {last_var} "@streq {last_val}"')

    return "\n".join(rule_lines)


def render_modsec_rules() -> str:
    block_rules = BlockRule.objects.all()
    rules_output = []

    for br in block_rules:
        rule_str = generate_modsec_rule(br)
        if rule_str:
            rules_output.append(rule_str)

    return rules_output


def get_country_info(ip_address):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip_address)
            country_name = response.country.name
            country_code = response.country.iso_code.lower()
            return {
                "country_name": country_name,
                "flag_url": f"https://flagcdn.com/w40/{country_code}.png",
            }
    except geoip2.errors.AddressNotFoundError:
        # Handle cases where the IP address is not found in the database
        return {"country_name": "Unknown", "flag_url": ""}
    except Exception as e:
        # Log other exceptions
        print(f"Error resolving IP {ip_address}: {e}")
        return {"country_name": "Unknown", "flag_url": ""}

def sort_logs_by_time(logs):
    return sorted(logs, key=lambda log: datetime.fromisoformat(log["time"]))

def is_static_file(log_entry):
    path = log_entry.get("path", "")
    # Match paths ending with excluded extensions
    return any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS)

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
    if request.user.is_superuser:
      domains = { "domains" : Domain.objects.all() }
    else:
      domains = { "domains" : Domain.objects.filter(owner=request.user) }
    return render(request, "main/domain.html", domains)

@login_required(login_url="/dashboard/")
def volumesnapshots(request,domain):
    try:
      if request.user.is_superuser:
        domain_obj = Domain.objects.get(domain_name=domain)
      else:
        domain_obj = Domain.objects.get(owner=request.user, domain_name=domain)
    except:
      return HttpResponse("Permission denied")
    context = {"volumesnapshots" : Volumesnapshot.objects.filter(domain=domain_obj), "domain" : domain }
    return render(request, "main/volumesnapshot.html", context)

def settings(request):
    return render(request, "main/settings.html")

def get_pods_status(request):
    if request.user.is_superuser:
      host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
      port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
      token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
      ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
      
      try:
          with open(token_path, 'r') as f:
              token = f.read().strip()
      except FileNotFoundError:
          return JsonResponse({"error": "Kubernetes token file not found."}, status=500)
  
      headers = {
          "Authorization": f"Bearer {token}",
          "Content-Type": "application/json"
      }
  
      # Get pods information across all namespaces
      url = f"https://{host}:{port}/api/v1/pods"
      try:
          response = requests.get(url, headers=headers, verify=ca_cert_path)
          response.raise_for_status()
          data = response.json()
      except requests.exceptions.RequestException as e:
          return JsonResponse({"error": str(e)}, status=500)
  
      pods_info = []
      for pod in data.get("items", []):
          metadata = pod.get("metadata", {})
          spec = pod.get("spec", {})
          status = pod.get("status", {})
  
          # Check if deletionTimestamp is set -> Pod is Terminating
          if metadata.get("deletionTimestamp"):
              pod_phase = "Terminating"
          else:
              pod_phase = status.get("phase", "Unknown")
  
          pods_info.append({
              "name": metadata.get("name"),
              "namespace": metadata.get("namespace"),
              "node": spec.get("nodeName", "Unknown"),
              "status": pod_phase,
              "ip": status.get("podIP", "N/A"),
              "host_ip": status.get("hostIP", "N/A"),
              "containers": len(spec.get("containers", [])),
          }) 
      return render(request, "main/pods_status.html", {"pods": pods_info})

@login_required(login_url="/dashboard/")
def livetraffic(request):
    if request.user.is_superuser:
      host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
      port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
      token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
      ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
      with open(token_path, 'r') as f:
        token = f.read().strip()
      headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"application/json"
      }
      namespace = "ingress"
      url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods"
      response = requests.get(url, headers=headers, verify=ca_cert_path)
      response.raise_for_status()
      
      pods = response.json()["items"]
      logs = []
      for pod in pods:
          pod_name = pod["metadata"]["name"]
          log_url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods/{pod_name}/log?sinceSeconds=3600"
          response = requests.get(log_url, headers=headers, verify=ca_cert_path)
      
          if response.status_code == 200:
              pod_logs = []
              for line in response.text.splitlines():
                  if not line.strip():
                      continue
                  try:
                      parsed_line = json.loads(line)
                      parsed_line["pod_name"] = pod_name  # Add metadata
                      if not is_static_file(parsed_line):
                          pod_logs.append(parsed_line)
                  except json.JSONDecodeError:
                      print(f"Skipping non-JSON line: {line}")
              logs.extend(pod_logs)
      logs = sort_logs_by_time(logs)
      for log in logs:
          ip = log.get("x_forwarded_for", "").split(",")[0].strip()  # Handle multiple forwarded IPs
          if ip:
              country_info = get_country_info(ip)
              log["country_name"] = country_info["country_name"]
              log["flag_url"] = country_info["flag_url"]
      return render(request, "main/livetraffic.html", {"logs": logs})
    else:
      return HttpResponse("Permission denied")
    
def logout_view(request):
    logout(request)
    return render(request, "login/login.html")

def generate_scp_port():
    scp_port_taken = 1
    while(scp_port_taken):
      scp_port = random.randint(30000,32767)
      scp_port_taken = Domain.objects.filter(scp_port=scp_port)
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
        #form = DomainAddForm(request.POST)
        try:
          new_domain_name = request.POST["domain_name"][:60]
          mem_limit = request.POST["mem_limit"][:8]
          cpu_limit = request.POST["cpu_limit"][:5]
          storage_size = request.POST["storage_size"][:5]
        except:
          return render(request, "main/add_domain.html")
        try:
          if request.POST["wordpress_preinstall"] == '1':
            wp_preinstall = True
          else:
            wp_preinstall = False
        except:
          wp_preinstall = False
        try:
          if request.POST["auto_dns"] == '1':
            api_token = request.POST["api_token"]
            auto_dns = True
          else:
            auto_dns = False
        except:
          auto_dns = False
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
        new_domain = Domain(owner=request.user, mem_limit = mem_limit, cpu_limit = cpu_limit, storage_size = storage_size, domain_name = new_domain_name, title = new_domain_name, scp_privkey = private_key, scp_pubkey = public_key, scp_port = scp_port, dkim_privkey = dkim_privkey, dkim_pubkey = dkim_txt_record, mariadb_pass = mariadb_pass, mariadb_user = mariadb_user, status = status)
        domain_dirname = '/kubepanel/yaml_templates/'+new_domain_name
        context = { "domain_instance" : new_domain, "domains" : Domain.objects.all(), "jobid" : jobid, "domain_name_dash" : new_domain.domain_name.replace(".","-"), "domain_name_underscore" : new_domain.domain_name.replace(".","_"), "domain_name" : new_domain.domain_name, "public_key" : public_key, "scp_port" : scp_port, "dkim_privkey" : dkim_privkey, "wp_preinstall" : wp_preinstall}
        try:
          new_domain.full_clean()
          new_domain.save()
        except:
          print("Ooops, can't save domain, please check debug logs.")
          return render(request, "main/domain_error.html",{ "domain" : new_domain_name,})
        if auto_dns == True:
          try:
            ips = ClusterIP.objects.all().values_list("ip_address", flat=True)
            spf_record = "v=spf1 " + " ".join(f"ip4:{ip}" for ip in ips) + " -all"
            user_token = CloudflareAPIToken.objects.get(api_token=api_token, user=request.user)
            zone_id = create_cf_zone(new_domain_name, user_token)
            zone_obj = DNSZone.objects.create(name=new_domain_name, zone_id=zone_id, token=user_token)
            zone_obj.save()
            dkim_record_obj = DNSRecord(zone=zone_obj,record_type="TXT",name="default._domainkey",content=dkim_txt_record)
            response = create_dns_record_in_cloudflare(dkim_record_obj)
            dkim_record_obj.cf_record_id = response.id
            dkim_record_obj.save()
            spf_record_obj = DNSRecord(zone=zone_obj,record_type="TXT",name="@",content=spf_record)
            response = create_dns_record_in_cloudflare(spf_record_obj)
            spf_record_obj.cf_record_id = response.id
            spf_record_obj.save()
            for ip in ips:
              a_record_obj = DNSRecord(zone=zone_obj,record_type="A",name="@",content=ip)
              response = create_dns_record_in_cloudflare(a_record_obj)
              a_record_obj.cf_record_id = response.id
              a_record_obj.save()
            mx_record_obj = DNSRecord(zone=zone_obj,record_type="MX",name="@",content=new_domain_name,priority=10)
            response = create_dns_record_in_cloudflare(mx_record_obj)
            mx_record_obj.cf_record_id = response.id
            mx_record_obj.save()
          except Exception as e:
            logging.warning(f"Can't create DNS zone. Please check debug logs if you think this is an error: {e}")
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
        tokens = CloudflareAPIToken.objects.filter(user=request.user)
        form = DomainAddForm()
        return render(request, "main/add_domain.html", { "form" : form, "api_tokens" : tokens })

@login_required(login_url="/dashboard/")
def startstop_domain(request,domain,action):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
          permission_valid = Domain.objects.get(owner=request.user, domain_name = domain)
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
          if action == "start":
            replicas = 1
          if action == "stop":
            replicas = 0
          payload = {
 	   "spec": {
             "replicas": replicas
            }
          }
          urls = []
          urls.append(f"https://{host}:{port}/apis/apps/v1/namespaces/{namespace}/deployments/nginx")
          urls.append(f"https://{host}:{port}/apis/apps/v1/namespaces/{namespace}/deployments/php")
          for url in urls:
            try:
                response = requests.patch(url, headers=headers, data=json.dumps(payload), verify=False)  # Disable SSL verification for simplicity
                if response.status_code == 200:
                    print(f"Deployment nginx successfully scaled to {replicas} replicas.")
                else:
                    print(f"Failed to scale deployment. Status Code: {response.status_code}")
                    print(f"Response: {response.text}")
            except requests.exceptions.RequestException as e:
                print(f"Error while scaling deployment: {e}")
      else:
        error = "Domain name didn't match"
        return render(request, "main/pause_domain.html", { "action" : action, "domain" : domain, "error" : error})
    else:
      return render(request, "main/pause_domain.html", { "action" : action, "domain" : domain})  
    return redirect(kpmain)

@login_required(login_url="/dashboard/")
def restore_volumesnapshot(request,volumesnapshot,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
          domain_obj = Domain.objects.get(owner=request.user, domain_name = domain)
        except:
          return HttpResponse("Permission denied.")
        if domain_obj:
          storage_size = domain_obj.storage_size
          template_dir = "restore_templates/"
          domain_dirname = '/kubepanel/yaml_templates/'+domain
          try:
            os.mkdir(domain_dirname)
            os.mkdir('/dkim-privkeys/'+domain)
          except:
            print("Can't create directories. Please check debug logs if you think this is an error.")
          jobid = random_string(5)
          context = { "storage_size" : storage_size, "jobid" : jobid, "domain_name_underscore" : domain.replace(".","_"), "domain_name_dash" : domain.replace(".","-"), "volumesnapshot" : volumesnapshot }
          iterate_input_templates(template_dir,domain_dirname,context)
      else:
        error = "Domain name didn't match"
        return render(request, "main/restore_snapshot.html", { "volumesnapshot" : volumesnapshot, "domain" : domain, "error" : error})
    else:
      return render(request, "main/restore_snapshot.html", { "volumesnapshot" : volumesnapshot, "domain" : domain})
    return redirect(kpmain)

@login_required(login_url="/dashboard/")
def start_backup(request,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
          permission_valid = Domain.objects.get(owner=request.user, domain_name = domain)
        except:
          return HttpResponse("Permission denied.")
        if permission_valid:
          template_dir = "backup_templates/"
          domain_dirname = '/kubepanel/yaml_templates/'+domain
          try:
            os.mkdir(domain_dirname)
            os.mkdir('/dkim-privkeys/'+domain)
          except:
            print("Can't create directories. Please check debug logs if you think this is an error.")
          jobid = random_string(5)
          context = { "domain_name" : domain, "jobid" : jobid, "domain_name_underscore" : domain.replace(".","_"), "domain_name_dash" : domain.replace(".","-") }
          iterate_input_templates(template_dir,domain_dirname,context)
      else:
        error = "Domain name didn't match"
        return render(request, "main/start_backup.html", { "domain" : domain, "error" : error})
    else:
      return render(request, "main/start_backup.html", { "domain" : domain})
    return redirect(kpmain)

@login_required(login_url="/dashboard/")
def delete_domain(request,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
            domain_to_delete = Domain.objects.get(owner=request.user, domain_name = domain)
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
            context = { "jobid" : jobid, "domain_name_dash" : domain.replace(".","-"), "domain_name_underscore" : domain.replace(".","_")}
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
    if request.user.is_superuser:
      domain = Domain.objects.get(domain_name = domain)
    else:
      domain = Domain.objects.get(owner=request.user, domain_name = domain)
    form = DomainForm(instance=domain)
  except:
    return HttpResponse("Permission denied.")
  return render(request, "main/view_domain.html", { "domain" : domain, "form" : form})

@login_required(login_url="/dashboard/")
def save_domain(request,domain):
  domain_instance = Domain.objects.get(owner=request.user, domain_name = domain)
  if request.method == 'POST':
      form = DomainForm(request.POST, instance=domain_instance)
      if form.is_valid():
          form.save()
          template_dir = "yaml_templates/"
          domain_dirname = '/kubepanel/yaml_templates/'+domain_instance.domain_name
          try:
            os.mkdir(domain_dirname)
            os.mkdir('/dkim-privkeys/'+domain)
          except:
            print("Can't create directories. Please check debug logs if you think this is an error.")
          jobid = random_string(5)
          domain_instance = Domain.objects.get(owner=request.user, domain_name = domain)
          context = { "domain_instance" : domain_instance, "domain_name" : domain, "jobid" : jobid, "domain_name_underscore" : domain.replace(".","_"), "domain_name_dash" : domain.replace(".","-") }
          iterate_input_templates(template_dir,domain_dirname,context)
      else:
        return render(request, "main/view_domain.html", { "domain" : domain_instance, "form" : form})
  return redirect(kpmain)

@login_required
def list_mail_users(request):
    # Show only the mail accounts belonging to domains the user owns (if not superuser).
    if request.user.is_superuser:
        mail_users = MailUser.objects.all()
    else:
        mail_users = MailUser.objects.filter(domain__owner=request.user)
    return render(request, "main/list_mail_users.html", {"mail_users": mail_users})

@login_required
def create_mail_user(request):
    if request.method == 'POST':
        form = MailUserForm(request.POST)
        if form.is_valid():
            # Ensure the user owns the domain (if not superuser)
            if not request.user.is_superuser:
                domain_obj = form.cleaned_data['domain']
                if domain_obj.owner != request.user:
                    return render(request, "main/error.html", {"error": "You do not own this domain."})

            form.save()
            return redirect("list_mail_users")
    else:
        form = MailUserForm()
    return render(request, "main/create_mail_user.html", {"form": form})

@login_required
def edit_mail_user(request, user_id):
    mail_user = get_object_or_404(MailUser, pk=user_id)
    if not request.user.is_superuser and mail_user.domain.owner != request.user:
        return render(request, "main/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        form = MailUserForm(request.POST, instance=mail_user)
        if form.is_valid():
            form.save()
            return redirect("list_mail_users")
    else:
        # Initialize form with existing mail user data
        form = MailUserForm(instance=mail_user)
    return render(request, "main/edit_mail_user.html", {"form": form})

@login_required
def delete_mail_user(request, user_id):
    mail_user = get_object_or_404(MailUser, pk=user_id)
    if not request.user.is_superuser and mail_user.domain.owner != request.user:
        return render(request, "mail/error.html", {"error": "Permission denied."})
    
    if request.method == 'POST':
        mail_user.delete()
        return redirect("list_mail_users")
    return render(request, "mail/delete_mail_user.html", {"mail_user": mail_user})

