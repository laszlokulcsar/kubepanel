from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.http import JsonResponse, HttpResponse, FileResponse, StreamingHttpResponse, HttpResponseNotFound, HttpResponseServerError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from .models import PhpImage, Package, UserProfile, LogEntry, MailUser, MailAlias, ClusterIP, DNSZone, User, Domain, Volumesnapshot, BlockRule, DNSRecord, CloudflareAPIToken
from dashboard.forms import UserProfilePackageForm, UserForm, PackageForm, UserProfileForm, MailUserForm, MailAliasForm, DomainForm, DomainAddForm, DomainAliasForm, APITokenForm, ZoneCreationForm, DNSRecordForm
from django.urls import reverse, reverse_lazy
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from datetime import datetime
from cloudflare import Cloudflare
from django.contrib import messages
from django.contrib.contenttypes.models import ContentType
from django.views.generic import ListView, CreateView, UpdateView, FormView
from django.contrib.auth.models import User
from django.db.models import Sum
from django.db import transaction
from django.views import View
from django.conf import settings
from kubernetes import client, config
from kubernetes.stream import stream
from kubernetes.client import ApiException
import subprocess, legacycrypt as crypt, time, cloudflare, logging, os, random, base64, string, requests, json, geoip2.database

from .services.dns_service import (
    CloudflareDNSService,
    DNSZoneManager,
    DNSRecordData,
    CloudflareAPIException,
    generate_email_dns_records
)

GEOIP_DB_PATH = "/kubepanel/GeoLite2-Country.mmdb"
TEMPLATE_BASE = "/kubepanel/dashboard/templates/"
EXCLUDED_EXTENSIONS = [".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"]
UPLOAD_BASE_DIR = getattr(settings, 'WATCHDOG_UPLOAD_ROOT', '/kubepanel/watchdog/uploads')

logger = logging.getLogger("django")


class SuperuserRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_superuser

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
    """
    Delete DNS zone from both Cloudflare and database
    Only allows deletion if the zone has no DNS records
    """
    zone = get_object_or_404(DNSZone, id=zone_id, token__user=request.user)
    
    # Check if zone has any DNS records
    record_count = zone.dns_records.count()
    has_records = record_count > 0
    
    if request.method == "POST":
        # Double-check that zone has no records before allowing deletion
        if has_records:
            messages.error(request, f"Cannot delete zone '{zone.name}' because it contains {record_count} DNS record(s). Please delete all records first.")
            return redirect("list_dns_records", zone_id=zone.id)
        
        try:
            zone_name = zone.name
            
            # Delete from Cloudflare
            try:
                dns_service = CloudflareDNSService(zone.token.api_token)
                dns_service._retry_api_call(
                    dns_service.client.zones.delete,
                    zone_id=zone.zone_id
                )
                logger.info(f"Successfully deleted zone {zone_name} from Cloudflare")
            except CloudflareAPIException as e:
                logger.error(f"Failed to delete zone from Cloudflare: {e}")
                messages.error(request, f"Failed to delete zone from Cloudflare: {e.message}")
                return redirect("zones_list")
            except Exception as e:
                logger.error(f"Unexpected error deleting zone from Cloudflare: {e}")
                messages.error(request, f"Failed to delete zone from Cloudflare: {str(e)}")
                return redirect("zones_list")
            
            # Delete from database
            zone.delete()
            messages.success(request, f"DNS Zone '{zone_name}' deleted successfully.")
            
            # Log the deletion
            logger.info(f"User {request.user.username} deleted DNS zone {zone_name}")
            
            return redirect("zones_list")
            
        except Exception as e:
            logger.error(f"Error deleting zone: {e}")
            messages.error(request, f"Error deleting zone: {e}")
            return redirect("zones_list")
    
    # GET request - show confirmation page
    return render(request, "main/delete_zone_confirm.html", {
        "zone": zone,
        "has_records": has_records,
        "record_count": record_count,
        "type": "DNS Zone"
    })

def delete_dns_record(request, record_id):
    """
    Delete DNS record from both Cloudflare and database
    Enhanced version of your existing function
    """
    record = get_object_or_404(DNSRecord, id=record_id, zone__token__user=request.user)

    if request.method == "POST":
        try:
            record_name = record.name
            record_type = record.record_type

            # Use your existing DNS service
            dns_service = CloudflareDNSService(record.zone.token.api_token)

            # Delete from Cloudflare first
            if record.cf_record_id:
                try:
                    dns_service._retry_api_call(
                        dns_service.client.dns.records.delete,
                        zone_id=record.zone.zone_id,
                        dns_record_id=record.cf_record_id
                    )
                    logger.info(f"Successfully deleted DNS record {record_name} from Cloudflare")
                except CloudflareAPIException as e:
                    logger.error(f"Failed to delete from Cloudflare: {e}")
                    messages.error(request, f"Failed to delete from Cloudflare: {e.message}")
                    return redirect("list_dns_records", zone_id=record.zone.id)
                except Exception as e:
                    logger.error(f"Unexpected Cloudflare error: {e}")
                    messages.error(request, f"Failed to delete from Cloudflare: {str(e)}")
                    return redirect("list_dns_records", zone_id=record.zone.id)

            # Delete from database
            zone_id = record.zone.id
            record.delete()

            messages.success(request, f'DNS record "{record_name}" ({record_type}) deleted successfully.')
            return redirect("list_dns_records", zone_id=zone_id)

        except Exception as e:
            logger.error(f"Error deleting DNS record: {e}")
            messages.error(request, f"Error deleting record: {e}")
            return redirect("list_dns_records", zone_id=record.zone.id)

    # GET request - show confirmation page
    return render(request, "main/delete_dns_record_confirm.html", {
        "record": record,
        "zone": record.zone,
        "type": "DNS Record"
    })


@login_required
def bulk_delete_dns_records(request):
    """
    Delete multiple DNS records at once via AJAX
    """
    if request.method != "POST":
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
        record_ids = data.get('record_ids', [])

        if not record_ids:
            return JsonResponse({
                'status': 'error',
                'message': 'No records selected for deletion.'
            }, status=400)

        # Get records belonging to the user
        dns_records = DNSRecord.objects.filter(
            id__in=record_ids,
            zone__token__user=request.user
        ).select_related('zone', 'zone__token')

        if not dns_records.exists():
            return JsonResponse({
                'status': 'error',
                'message': 'No valid records found for deletion.'
            }, status=404)

        deleted_count = 0
        failed_count = 0
        failed_records = []

        # Group records by zone to use appropriate DNS service
        zones = {}
        for record in dns_records:
            if record.zone.id not in zones:
                zones[record.zone.id] = {
                    'dns_service': CloudflareDNSService(record.zone.token.api_token),
                    'zone_id': record.zone.zone_id,
                    'records': []
                }
            zones[record.zone.id]['records'].append(record)

        # Delete records zone by zone
        for zone_data in zones.values():
            dns_service = zone_data['dns_service']
            zone_id = zone_data['zone_id']

            for record in zone_data['records']:
                try:
                    # Delete from Cloudflare first
                    if record.cf_record_id:
                        dns_service._retry_api_call(
                            dns_service.client.dns.records.delete,
                            zone_id=zone_id,
                            dns_record_id=record.cf_record_id
                        )

                    # Delete from database
                    record.delete()
                    deleted_count += 1

                except Exception as e:
                    logger.error(f"Failed to delete record {record.name}: {e}")
                    failed_count += 1
                    failed_records.append(f"{record.name} ({record.record_type})")

        if failed_count == 0:
            return JsonResponse({
                'status': 'success',
                'message': f'Successfully deleted {deleted_count} DNS records.'
            })
        elif deleted_count > 0:
            return JsonResponse({
                'status': 'partial',
                'message': f'Deleted {deleted_count} records. Failed: {", ".join(failed_records)}'
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': f'Failed to delete any records. Errors: {", ".join(failed_records)}'
            }, status=500)

    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Bulk delete error: {e}")
        return JsonResponse({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }, status=500)

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
    Legacy function - creates a DNS record in Cloudflare based on the DNSRecord instance.
    This is a simplified version of your original function using the new service.
    """
    try:
        dns_service = CloudflareDNSService(record_obj.zone.token.api_token)
        record_data = DNSRecordData(
            record_type=record_obj.record_type,
            name=record_obj.name,
            content=record_obj.content,
            ttl=record_obj.ttl,
            proxied=record_obj.proxied,
            priority=record_obj.priority
        )
        response = dns_service.create_dns_record(record_obj.zone.zone_id, record_data)
        return response
    except Exception as e:
        logger.error(f"Error in legacy create_dns_record_in_cloudflare: {e}")
        raise

# Your original create_cf_zone function - simplified version
def create_cf_zone(zone_name, token):
    """
    Legacy function - creates a zone in Cloudflare using the given token.
    This is a simplified version using the new service.
    """
    try:
        dns_service = CloudflareDNSService(token.api_token)
        return dns_service.create_zone(zone_name)
    except Exception as e:
        logger.error(f"Error in legacy create_cf_zone: {e}")
        raise

def create_dns_record(request):
    """Create a single DNS record"""
    zone_id = request.GET.get('zone')
    zone = None

    if zone_id:
        zone = get_object_or_404(DNSZone, id=zone_id)

    if request.method == "POST":
        # Initialize form with POST data
        form = DNSRecordForm(request.POST, user=request.user)

        # If zone is pre-selected from URL, we need to handle it specially
        if zone and 'zone' not in request.POST:
            # Create a mutable copy of POST data
            post_data = request.POST.copy()
            post_data['zone'] = zone.id
            form = DNSRecordForm(post_data, user=request.user)

        logger.info(f"Form data: {request.POST}")
        logger.info(f"Zone from URL: {zone}")

        if form.is_valid():
            logger.info(f"Form cleaned data: {form.cleaned_data}")

            try:
                # Create the record object without saving
                record_obj = form.save(commit=False)

                # If zone was passed via URL, override the form's zone
                if zone:
                    record_obj.zone = zone

                logger.info(f"Creating record: {record_obj.record_type} {record_obj.name} -> {record_obj.content}")
                logger.info(f"Zone: {record_obj.zone}")

                # Use the service to create the record in Cloudflare
                dns_service = CloudflareDNSService(record_obj.zone.token.api_token)
                record_data = DNSRecordData(
                    record_type=record_obj.record_type,
                    name=record_obj.name,
                    content=record_obj.content,
                    ttl=record_obj.ttl,
                    proxied=record_obj.proxied,
                    priority=record_obj.priority
                )

                # Create in Cloudflare and save to DB in a transaction
                with transaction.atomic():
                    cf_record = dns_service.create_dns_record(record_obj.zone.zone_id, record_data)

                    # Extract record ID from response
                    if hasattr(cf_record, 'id'):
                        record_obj.cf_record_id = cf_record.id
                    elif isinstance(cf_record, dict) and 'id' in cf_record:
                        record_obj.cf_record_id = cf_record['id']
                    else:
                        logger.error(f"Unexpected Cloudflare response format: {cf_record}")
                        raise ValueError("Could not extract record ID from Cloudflare response")

                    # Now save to database
                    record_obj.save()
                    logger.info(f"DNS record saved with ID: {record_obj.id}, CF ID: {record_obj.cf_record_id}")

                messages.success(request, "DNS record created successfully.")
                return redirect("list_dns_records", zone_id=record_obj.zone.id)

            except CloudflareAPIException as e:
                logger.error(f"Cloudflare API error: {e}")
                messages.error(request, f"Cloudflare API error: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error creating DNS record: {e}", exc_info=True)
                messages.error(request, "An unexpected error occurred. Please try again.")
        else:
            logger.error(f"Form errors: {form.errors}")
            messages.error(request, "Please correct the form errors.")
    else:
        # GET request
        initial_data = {}
        if zone:
            initial_data['zone'] = zone.id

        form = DNSRecordForm(user=request.user, initial=initial_data)

    return render(request, "main/create_dns_record.html", {
        "form": form,
        "zone": zone,
        "zone_id": zone_id
    })

def create_zone(request):
    """Create a DNS zone"""
    if request.method == "POST":
        form = ZoneCreationForm(request.user, request.POST)
        if form.is_valid():
            zone_name = form.cleaned_data["zone_name"]
            user_token = form.cleaned_data["token"]

            try:
                zone_manager = DNSZoneManager(user_token)
                zone_obj, _ = zone_manager.create_zone_with_records(zone_name, [])
                messages.success(request, f"Zone '{zone_name}' created successfully.")

            except CloudflareAPIException as e:
                logger.error(f"Cloudflare API error creating zone: {e}")
                messages.error(request, f"Failed to create zone: {e.message}")
            except Exception as e:
                logger.error(f"Unexpected error creating zone: {e}")
                messages.error(request, "An unexpected error occurred. Please try again.")

            return redirect("zones_list")
    else:
        form = ZoneCreationForm(request.user)

    return render(request, "main/create_zone.html", {"form": form})

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
        return redirect("blocked_objects")

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
        return redirect("blocked_objects")
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
            f'"phase:1,id:{rule_id},deny,msg:\"{msg_string}\""'
        )

    rule_lines = []

    first_var, first_val = conditions[0]
    rule_lines.append(
        f'SecRule {first_var} "@streq {first_val}" '
        f'"phase:1,id:{rule_id},deny,chain,msg:\"{msg_string}\""'
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
      domains = Domain.objects.all()
      pkg = getattr(request.user.profile, 'package', None)
      totals = domains.aggregate(
          total_storage=Sum('storage_size'),
          total_cpu=Sum('cpu_limit'),
          total_mem=Sum('mem_limit'),
      )
      total_storage = totals['total_storage'] or 0
      total_cpu     = totals['total_cpu']     or 0
      total_mem     = totals['total_mem']     or 0
      total_mail_users    = MailUser.objects.filter(domain__owner=request.user).count()
      total_domain_aliases = sum(d.aliases.count() for d in domains)
    else:
      domains = Domain.objects.filter(owner=request.user)
      pkg = getattr(request.user.profile, 'package', None)
      totals = domains.aggregate(
          total_storage=Sum('storage_size'),
          total_cpu=Sum('cpu_limit'),
          total_mem=Sum('mem_limit'),
      )
      total_storage = totals['total_storage'] or 0
      total_cpu     = totals['total_cpu']     or 0
      total_mem     = totals['total_mem']     or 0
      total_mail_users    = MailUser.objects.filter(domain__owner=request.user).count()
      total_domain_aliases = sum(d.aliases.count() for d in domains)
    return render(request, 'main/domain.html', {
        'domains': domains,
        'pkg': pkg,
        'total_storage': total_storage,
        'total_cpu': total_cpu,
        'total_mem': total_mem,
        'total_mail_users': total_mail_users,
        'total_domain_aliases': total_domain_aliases,
    })

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

@login_required
def get_pods_status(request):
    is_super = request.user.is_superuser

    label_selector = None
    if not is_super:
        # grab every domain_name this user owns
        user_domains = list(
            Domain.objects
                  .filter(owner=request.user)
                  .values_list("domain_name", flat=True)
        )

        # if they have none, just render empty list
        if not user_domains:
            return render(request, "main/pods_status.html", {"pods": []})

        # convert each foo.bar → foo-bar (to match your `group=` label)
        slugs = [d.replace(".", "-") for d in user_domains]

        # build an OR-based selector: group in (a,b,c)
        if len(slugs) == 1:
            label_selector = f"group={slugs[0]}"
        else:
            # note: no spaces inside the parens
            label_selector = f"group in ({','.join(slugs)})"

    # ——— Kubernetes API setup ———
    host         = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port         = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token_path   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    try:
        token = open(token_path).read().strip()
    except FileNotFoundError:
        return JsonResponse({"error": "Kubernetes token file not found."}, status=500)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    # apply labelSelector if this is a regular user
    url = f"https://{host}:{port}/api/v1/pods"
    if label_selector:
        url += f"?labelSelector={label_selector}"

    try:
        resp = requests.get(url, headers=headers, verify=ca_cert_path)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": str(e)}, status=500)

    # ——— build the same pods_info list as before ———
    pods_info = []
    for pod in items:
        md   = pod.get("metadata", {})
        spec = pod.get("spec", {})
        st   = pod.get("status", {})

        phase = "Terminating" if md.get("deletionTimestamp") else st.get("phase", "Unknown")

        pods_info.append({
            "name":       md.get("name"),
            "namespace":  md.get("namespace"),
            "node":       spec.get("nodeName", "Unknown"),
            "status":     phase,
            "ip":         st.get("podIP", "N/A"),
            "host_ip":    st.get("hostIP", "N/A"),
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
          php_image = PhpImage.objects.get(pk=request.POST["php_image"][:2])
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
        sftp_pass = random_string(12)
        salt = crypt.mksalt(crypt.METHOD_SHA512)
        sftp_pass_hash = crypt.crypt(sftp_pass, salt)
        jobid = random_string(5)
        mariadb_user = new_domain_name.replace(".","_").replace("-","_")
        status = "Startup in progress"
        new_domain = Domain(owner=request.user, sftp_pass = sftp_pass, php_image = php_image, mem_limit = mem_limit, cpu_limit = cpu_limit, storage_size = storage_size, domain_name = new_domain_name, title = new_domain_name, scp_privkey = private_key, scp_pubkey = public_key, scp_port = scp_port, dkim_privkey = dkim_privkey, dkim_pubkey = dkim_txt_record, mariadb_pass = mariadb_pass, mariadb_user = mariadb_user, status = status)
        domain_dirname = '/kubepanel/yaml_templates/'+new_domain_name
        context = { "sftp_pass_hash" : sftp_pass_hash, "domain_instance" : new_domain, "domains" : Domain.objects.all(), "jobid" : jobid, "domain_name_dash" : new_domain.domain_name.replace(".","-"), "domain_name_underscore" : new_domain.domain_name.replace(".","_"), "domain_name" : new_domain.domain_name, "public_key" : public_key, "scp_port" : scp_port, "dkim_privkey" : dkim_privkey, "wp_preinstall" : wp_preinstall}
        logger = logging.getLogger(__name__)
        try:
          new_domain.full_clean()
          new_domain.save()
          LogEntry.objects.create(content_object=new_domain,actor=f"user:{request.user.username}",user=request.user,level="INFO",message=f"Created domain {new_domain.domain_name}",data={"domain_id": new_domain.pk})
        except Exception as e:
          logger.error("Error adding domain: %s", e)
          return render(request, "main/domain_error.html",{ "domain" : new_domain_name, "error" : e,})
        if auto_dns == True:
          try:
              user_token = CloudflareAPIToken.objects.get(api_token=api_token, user=request.user)
              cluster_ips = list(ClusterIP.objects.values_list("ip_address", flat=True))

              # Generate all DNS records
              dns_records = generate_email_dns_records(new_domain_name, cluster_ips)

              # Add DKIM record
              dns_records.append(DNSRecordData(
                  record_type="TXT",
                  name="default._domainkey",
                  content=dkim_txt_record
              ))

              # Create zone with all records
              zone_manager = DNSZoneManager(user_token)
              zone_obj, created_records = zone_manager.create_zone_with_records(new_domain_name, dns_records)

              logger.info(f"Successfully created domain '{new_domain_name}' with {len(created_records)} DNS records")
              messages.success(request, f"Domain '{new_domain_name}' created with {len(created_records)} DNS records.")

          except CloudflareAPIToken.DoesNotExist:
              logger.error(f"API token not found for user {request.user}")
              messages.error(request, "Invalid API token.")
              raise ValueError("Invalid API token")
          except CloudflareAPIException as e:
              logger.error(f"Cloudflare API error: {e}")
              messages.error(request, f"Failed to create domain: {e.message}")
              raise
          except Exception as e:
              logger.error(f"Failed to create domain with auto DNS: {e}")
              messages.error(request, f"Failed to create domain: {str(e)}")
              raise
#          try:
#            ips = ClusterIP.objects.all().values_list("ip_address", flat=True)
#            spf_record = "v=spf1 " + " ".join(f"ip4:{ip}" for ip in ips) + " -all"
#            user_token = CloudflareAPIToken.objects.get(api_token=api_token, user=request.user)
#            zone_id = create_cf_zone(new_domain_name, user_token)
#            zone_obj = DNSZone.objects.create(name=new_domain_name, zone_id=zone_id, token=user_token)
#            zone_obj.save()
#            dkim_record_obj = DNSRecord(zone=zone_obj,record_type="TXT",name="default._domainkey",content=dkim_txt_record)
#            response = create_dns_record_in_cloudflare(dkim_record_obj)
#            dkim_record_obj.cf_record_id = response.id
#            dkim_record_obj.save()
#            dmarc_record_obj = DNSRecord(zone=zone_obj,record_type="TXT",name="_dmarc",content="v=DMARC1; p=none;")
#            response = create_dns_record_in_cloudflare(dmarc_record_obj)
#            dmarc_record_obj.cf_record_id = response.id
#            dmarc_record_obj.save()
#            spf_record_obj = DNSRecord(zone=zone_obj,record_type="TXT",name="@",content=spf_record)
#            response = create_dns_record_in_cloudflare(spf_record_obj)
#            spf_record_obj.cf_record_id = response.id
#            spf_record_obj.save()
#            counter = 0
#            for ip in ips:
#              a_record_obj = DNSRecord(zone=zone_obj,record_type="A",name="@",content=ip)
#              response = create_dns_record_in_cloudflare(a_record_obj)
#              a_record_obj.cf_record_id = response.id
#              a_record_obj.save()
#              a_record_obj = DNSRecord(zone=zone_obj,record_type="A",name="www",content=ip)
#              response = create_dns_record_in_cloudflare(a_record_obj)
#              a_record_obj.cf_record_id = response.id
#              a_record_obj.save()
#              a_record_obj = DNSRecord(zone=zone_obj,record_type="A",name="mx"+str(counter),content=ip)
#              response = create_dns_record_in_cloudflare(a_record_obj)
#              a_record_obj.cf_record_id = response.id
#              a_record_obj.save()
#              mx_record_obj = DNSRecord(zone=zone_obj,record_type="MX",name="@",content="mx"+str(counter)+"."+new_domain_name,priority=counter)
#              response = create_dns_record_in_cloudflare(mx_record_obj)
#              mx_record_obj.cf_record_id = response.id
#              mx_record_obj.save()
#              counter = counter + 1
#          except Exception as e:
#            logging.warning(f"Can't create DNS zone. Please check debug logs if you think this is an error: {e}")
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
        return redirect(domain_logs, domain=new_domain.domain_name)
    else:
        tokens = CloudflareAPIToken.objects.filter(user=request.user)
        form = DomainAddForm()
        return render(request, "main/add_domain.html", { "form" : form, "api_tokens" : tokens })

@login_required(login_url="/dashboard/")
def startstop_domain(request,domain,action):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
          domain_obj = Domain.objects.get(domain_name = domain)
          if request.user.is_superuser or domain_obj.owner == request.user:
            permission_valid = True
          else:
            permission_valie = False
            return HttpResponse("Permission denied.")
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
          if action == "start":
              LogEntry.objects.create(content_object=domain_obj,actor=f"user:{request.user.username}",user=request.user,level="INFO",message=f"Started domain {domain_obj.domain_name}",data={"domain_id": domain_obj.pk})
          if action == "stop":
              LogEntry.objects.create(content_object=domain_obj,actor=f"user:{request.user.username}",user=request.user,level="INFO",message=f"Paused domain {domain_obj.domain_name}",data={"domain_id": domain_obj.pk})
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
    return redirect(domain_logs, domain=domain_obj.domain_name)

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
          context = { "storage_size" : storage_size, "jobid" : jobid, "domain_name_underscore" : domain.replace(".","_"), "domain_name_dash" : domain.replace(".","-"), "volumesnapshot" : volumesnapshot, "domain" : domain }
          iterate_input_templates(template_dir,domain_dirname,context)
          LogEntry.objects.create(content_object=domain_obj,actor=f"user:{request.user.username}",user=request.user,level="INFO",message=f"Restore started for {domain_obj.domain_name}",data={"domain_id": domain_obj.pk})
      else:
        error = "Domain name didn't match"
        return render(request, "main/restore_snapshot.html", { "volumesnapshot" : volumesnapshot, "domain" : domain, "error" : error})
    else:
      return render(request, "main/restore_snapshot.html", { "volumesnapshot" : volumesnapshot, "domain" : domain})
    return redirect(domain_logs, domain=domain_obj.domain_name)

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
          return redirect('backup_logs', domain=domain, jobid=jobid)
      else:
        error = "Domain name didn't match"
        return render(request, "main/start_backup.html", { "domain" : domain, "error" : error})
    else:
      return render(request, "main/start_backup.html", { "domain" : domain})

@login_required(login_url="/dashboard/")
def delete_domain(request,domain):
    if request.method == 'POST':
      if request.POST["imsure"] == domain:
        try:
            domain_obj = Domain.objects.get(domain_name = domain)
            if domain_obj.owner == request.user or request.user.is_superuser:
                permission_valid = True
            else:
                permission_valid = False
                return HttpResponse("Permission denied.")
        except:
            return HttpResponse("Permission denied.")
        if permission_valid:
            domain_dirname = '/kubepanel/yaml_templates/'+domain
            try:
              os.mkdir(domain_dirname)
              os.mkdir('/dkim-privkeys/'+domain)
            except:
              print("Can't create directories. Please check debug logs if you think this is an error.")
            jobid = random_string(5)
            context = { "domain_name" : domain, "jobid" : jobid, "domain_name_dash" : domain.replace(".","-"), "domain_name_underscore" : domain.replace(".","_"), "mariadb_user" : domain.replace(".","_").replace("-","_")}
            template_dir = "delete_templates/"
            iterate_input_templates(template_dir,domain_dirname,context)
            domain_obj.delete()
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
  domain_instance = Domain.objects.get(domain_name = domain)
  if domain_instance.owner == request.user or request.user.is_superuser:
    if request.method == 'POST':
        form = DomainForm(request.POST, instance=domain_instance)
        if form.is_valid():
            form.save()
            LogEntry.objects.create(content_object=domain_instance,actor=f"user:{request.user.username}",user=request.user,level="INFO",message=f"New settings saved for {domain_instance.domain_name}",data={"domain_id": domain_instance.pk})
            template_dir = "yaml_templates/"
            domain_dirname = '/kubepanel/yaml_templates/'+domain_instance.domain_name
            try:
              os.mkdir(domain_dirname)
              os.mkdir('/dkim-privkeys/'+domain)
            except:
              print("Can't create directories. Please check debug logs if you think this is an error.")
            jobid = random_string(5)
            sftp_pass = domain_instance.sftp_pass
            salt = crypt.mksalt(crypt.METHOD_SHA512)
            sftp_pass_hash = crypt.crypt(sftp_pass, salt)
            context = { "domain_instance" : domain_instance, "sftp_pass_hash" : sftp_pass_hash, "domain_name" : domain, "jobid" : jobid, "domain_name_underscore" : domain.replace(".","_"), "domain_name_dash" : domain.replace(".","-") }
            iterate_input_templates(template_dir,domain_dirname,context)
        else:
          return render(request, "main/view_domain.html", { "domain" : domain_instance, "form" : form})
  else:
    return HttpResponse("Permission denied.")
  return redirect(domain_logs, domain=domain_instance.domain_name)

@login_required
def list_mail_users(request):
    if request.user.is_superuser:
        mail_users = MailUser.objects.all()
    else:
        mail_users = MailUser.objects.filter(domain__owner=request.user)
    return render(request, "main/list_mail_users.html", {"mail_users": mail_users})

@login_required
def create_mail_user(request):
    if request.method == 'POST':
        form = MailUserForm(request.POST, user=request.user)
        if form.is_valid():
            # Ensure the user owns the domain (if not superuser)
            if not request.user.is_superuser:
                domain_obj = form.cleaned_data['domain']
                if domain_obj.owner != request.user:
                    return render(request, "main/error.html", {"error": "You do not own this domain."})

            form.save()
            return redirect("list_mail_users")
    else:
        form = MailUserForm(user=request.user)
    return render(request, "main/create_mail_user.html", {"form": form})

@login_required
def edit_mail_user(request, user_id):
    mail_user = get_object_or_404(MailUser, pk=user_id)
    aliases   = MailAlias.objects.filter(destination__iexact=mail_user.email)
    if not request.user.is_superuser and mail_user.domain.owner != request.user:
        return render(request, "main/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        form = MailUserForm(request.POST, instance=mail_user)
        if form.is_valid():
            if not request.user.is_superuser:
                domain_obj = form.cleaned_data['domain']
                if domain_obj.owner != request.user:
                    return render(request, "main/error.html", {"error": "You do not own this domain."})
            form.save()
            return redirect("list_mail_users")
    else:
        # Initialize form with existing mail user data
        form = MailUserForm(user=request.user, instance=mail_user)
    return render(request, "main/edit_mail_user.html", {"form": form, 'mail_user': mail_user, 'aliases': aliases,})

@login_required
def delete_mail_user(request, user_id):
    mail_user = get_object_or_404(MailUser, pk=user_id)
    if not request.user.is_superuser and mail_user.domain.owner != request.user:
        return render(request, "mail/error.html", {"error": "Permission denied."})

    if request.method == 'POST':
        mail_user.delete()
        return redirect("list_mail_users")
    return render(request, "main/delete_mail_user.html", {"mail_user": mail_user})

@login_required
def alias_list(request, pk):
    domain = get_object_or_404(Domain, pk=pk)
    aliases = domain.aliases.order_by('created_at')
    return render(request, 'main/list_aliases.html', {'domain': domain, 'aliases': aliases})

@login_required
def alias_add(request, pk):
    domain = get_object_or_404(Domain, pk=pk)
    if request.method == 'POST':
        form = DomainAliasForm(request.POST)
        if form.is_valid():
            alias = form.save(commit=False)
            alias.domain = domain
            alias.save()
            domain_dirname = '/kubepanel/yaml_templates/'+alias.alias_name
            context = { "domain" : domain, "domain_name_dash" : domain.domain_name.replace(".","-")}
            template_dir = "alias_templates/"
            try:
              os.mkdir(domain_dirname)
              os.mkdir('/dkim-privkeys/'+new_domain_name)
            except:
              print("Can't create directories. Please check debug logs if you think this is an error.")
            iterate_input_templates(template_dir,domain_dirname,context)
            return redirect('view_domain', pk=domain.pk)
    else:
        form = DomainAliasForm()
    return render(request, 'main/add_alias.html', {'domain': domain, 'form': form})

@login_required
def alias_delete(request, pk):
    alias = get_object_or_404(DomainAlias, pk=pk)
    domain = alias.domain
    if request.method == 'POST':
        alias.delete()
        return redirect('alias_list', pk=domain.pk)
    return render(request, 'main/delete_alias.html', {'alias': alias})

@login_required
def mail_alias_list(request):
    qs = MailAlias.objects.select_related('domain')
    if not request.user.is_superuser:
        qs = qs.filter(domain__owner=request.user)
    return render(request, 'main/mail_alias_list.html', {
        'aliases': qs.order_by('source'),
    })

@login_required
def mail_alias_create(request):
    # pull ?destination=foo@bar.com from the URL
    initial = {}
    dest = request.GET.get('destination')
    if dest:
        initial['destination'] = dest

    if request.method == 'POST':
        form = MailAliasForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            return redirect('list_mail_users')
    else:
        form = MailAliasForm(initial=initial, user=request.user)

    return render(request, 'main/mail_alias_form.html', {'form': form})

@login_required
def mail_alias_edit(request, pk):
    alias = get_object_or_404(MailAlias, pk=pk)
    if not request.user.is_superuser and alias.domain.owner != request.user:
        return redirect('mail_alias_list')

    if request.method == 'POST':
        form = MailAliasForm(request.POST, instance=alias, user=request.user)
        if form.is_valid():
            form.save()
            return redirect('mail_alias_list')
    else:
        form = MailAliasForm(instance=alias, user=request.user)

    return render(request, 'main/mail_alias_form.html', {
        'form': form,
        'alias': alias,
    })

@login_required
def mail_alias_delete(request, pk):
    alias = get_object_or_404(MailAlias, pk=pk)
    if not request.user.is_superuser and alias.domain.owner != request.user:
        return redirect('list_mail_users')

    if request.method == 'POST':
        alias.delete()
        return redirect('list_mail_users')

    return render(request, 'main/mail_alias_confirm_delete.html', {
        'alias': alias,
    })

@login_required
def firewall_rule_delete(request, pk):
    block = get_object_or_404(BlockRule, pk=pk)

    if request.method == 'POST':
        block.delete()
        messages.success(request, f"Deleted rule #{pk}.")
    return redirect('blocked_objects')  # name of your list‐view URL

def _load_k8s_auth():
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_cert   = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

    try:
        token = open(token_path).read().strip()
    except FileNotFoundError:
        raise RuntimeError("Kubernetes token file not found")

    base = f"https://{host}:{port}"
    headers = {
        "Authorization": f"Bearer {token}",
        # we'll override Content-Type when patching
    }
    return base, headers, ca_cert

@login_required
def node_list(request):
    if not request.user.is_superuser:
        return redirect("node_list")  # or 403

    try:
        base, headers, verify = _load_k8s_auth()
        resp = requests.get(f"{base}/api/v1/nodes", headers=headers, verify=verify)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except Exception as e:
        messages.error(request, f"Failed to list nodes: {e}")
        items = []

    nodes = []
    for item in items:
        # pick InternalIP if present
        addrs = item["status"].get("addresses", [])
        ip = next((a["address"] for a in addrs if a["type"]=="InternalIP"), None)
        ip = ip or (addrs[0]["address"] if addrs else "–")

        conds = {c["type"]: c["status"] for c in item["status"].get("conditions", [])}
        ready = conds.get("Ready") == "True"
        unsched = item["spec"].get("unschedulable", False)

        status = "Ready" if ready and not unsched else (
                 "Unschedulable" if unsched else "NotReady"
        )
        nodes.append({
            "name":       item["metadata"]["name"],
            "ip":         ip,
            "start_time": item["metadata"]["creationTimestamp"],
            "status":     status,
        })

    return render(request, "main/node_list.html", {"nodes": nodes})

@login_required
def node_detail(request, name):
    if not request.user.is_superuser:
        return redirect("node_list")

    try:
        base, headers, verify = _load_k8s_auth()
        # get node object
        r_node = requests.get(f"{base}/api/v1/nodes/{name}", headers=headers, verify=verify)
        r_node.raise_for_status()
        node = r_node.json()

        # get events for this node
        sel = f"involvedObject.kind=Node,involvedObject.name={name}"
        r_evt = requests.get(f"{base}/api/v1/events?fieldSelector={sel}",
                             headers=headers, verify=verify)
        r_evt.raise_for_status()
        events = r_evt.json().get("items", [])
    except Exception as e:
        messages.error(request, f"Failed to fetch node detail: {e}")
        node, events = None, []

    return render(request, "main/node_detail.html", {
        "node":   node,
        "events": events,
    })

@login_required
def node_cordon(request, name):
    if not request.user.is_superuser:
        return redirect('node_list')

    if request.method == "POST":
        try:
            base, headers, verify = _load_k8s_auth()

            # use strategic merge patch
            patch_headers = headers.copy()
            patch_headers["Content-Type"] = "application/strategic-merge-patch+json"

            body = {"spec": {"unschedulable": True}}
            resp = requests.patch(
                f"{base}/api/v1/nodes/{name}",
                json=body,
                headers=patch_headers,
                verify=verify
            )

            # Debugging: log status and body if not 200
            if not resp.ok:
                messages.error(request,
                    f"Cordon failed (status={resp.status_code}): {resp.text}"
                )
            else:
                messages.success(request, f"Node {name} cordoned successfully.")

        except Exception as e:
            messages.error(request, f"Cordon exception: {e}")

    return redirect('node_list')


@login_required
def node_drain(request, name):
    if not request.user.is_superuser:
        return redirect('node_list')

    if request.method == "POST":
        try:
            base, headers, verify = _load_k8s_auth()

            # 1) cordon first (same merge-patch headers)
            patch_headers = headers.copy()
            patch_headers["Content-Type"] = "application/strategic-merge-patch+json"
            cordon_body = {"spec": {"unschedulable": True}}
            r1 = requests.patch(
                f"{base}/api/v1/nodes/{name}",
                json=cordon_body,
                headers=patch_headers,
                verify=verify
            )
            if not r1.ok:
                messages.error(request,
                    f"Cordon in drain failed (status={r1.status_code}): {r1.text}"
                )
                return redirect('node_list')

            # 2) list pods scheduled on this node
            sel = f"spec.nodeName={name}"
            r2 = requests.get(
                f"{base}/api/v1/pods?fieldSelector={sel}",
                headers=headers,
                verify=verify
            )
            r2.raise_for_status()
            pods = r2.json().get("items", [])

            # 3) evict each pod
            errors = []
            for p in pods:
                ns  = p["metadata"]["namespace"]
                pod = p["metadata"]["name"]
                eviction = {
                    "apiVersion": "policy/v1",
                    "kind":       "Eviction",
                    "metadata": {"name": pod, "namespace": ns}
                }
                ev_url = f"{base}/api/v1/namespaces/{ns}/pods/{pod}/eviction"
                rev = requests.post(
                    ev_url,
                    json=eviction,
                    headers=headers,
                    verify=verify
                )
                if not rev.ok:
                    errors.append(f"{pod}@{ns}: {rev.status_code}")

            if errors:
                messages.warning(
                    request,
                    f"Drained (cordoned) but evictions failed for: {', '.join(errors)}"
                )
            else:
                messages.success(request, f"Node {name} drained successfully.")

        except Exception as e:
            messages.error(request, f"Drain exception: {e}")

    return redirect('node_list')

@login_required
def node_uncordon(request, name):
    if not request.user.is_superuser:
        return redirect('node_list')

    if request.method == "POST":
        try:
            base, headers, verify = _load_k8s_auth()

            patch_headers = headers.copy()
            patch_headers["Content-Type"] = "application/strategic-merge-patch+json"

            body = {"spec": {"unschedulable": False}}
            resp = requests.patch(
                f"{base}/api/v1/nodes/{name}",
                json=body,
                headers=patch_headers,
                verify=verify
            )

            if not resp.ok:
                messages.error(
                    request,
                    f"Uncordon failed (status={resp.status_code}): {resp.text}"
                )
            else:
                messages.success(request, f"Node {name} uncordoned successfully.")

        except Exception as e:
            messages.error(request, f"Uncordon exception: {e}")

    return redirect('node_list')

@login_required
def pod_logs(request, namespace, name):
    is_super = request.user.is_superuser
    try:
        base, headers, verify = _load_k8s_auth()
    except Exception as e:
        messages.error(request, f"Error loading Kubernetes credentials: {e}")
        return redirect('pods_status')

    # 1) Fetch the Pod object
    try:
        pod_resp = requests.get(f"{base}/api/v1/namespaces/{namespace}/pods/{name}", headers=headers, verify=verify, timeout=10)
    except Exception as e:
        messages.error(request, f"Error fetching pod details: {e}")
        return redirect('pods_status')

    if not pod_resp.ok:
        messages.error(request, f"Could not fetch pod details (status={pod_resp.status_code}): {pod_resp.text}")
        return redirect('pods_status')

    pod_json = pod_resp.json()
    labels = pod_json.get('metadata', {}).get('labels', {})
    group_label = labels.get('group')

    # 2) Permission check for regular users
    if not is_super:
        user_slugs = [d.replace('.', '-') for d in Domain.objects.filter(owner=request.user).values_list('domain_name', flat=True)]
        if not group_label or group_label not in user_slugs:
            messages.error(request, "You are not authorized to view logs for this pod.")
            return redirect('pods_status')

    # 3) Discover containers
    container_specs = pod_json.get('spec', {}).get('containers', [])
    container_names = [c.get('name') for c in container_specs]

    # 4) Fetch logs per container
    logs_by_container = {}
    for c in container_names:
        try:
            log_resp = requests.get(f"{base}/api/v1/namespaces/{namespace}/pods/{name}/log", headers=headers, verify=verify, params={'container': c}, timeout=10)
            if log_resp.ok:
                logs_by_container[c] = log_resp.text.splitlines()
            else:
                messages.error(request, f"Failed to fetch logs for container “{c}” (status={log_resp.status_code}): {log_resp.text}")
                logs_by_container[c] = []
        except Exception as e:
            messages.error(request, f"Error fetching logs for container “{c}”: {e}")
            logs_by_container[c] = []

    return render(request, 'main/pod_logs.html', {'namespace': namespace, 'pod_name': name, 'logs_by_container': logs_by_container})

@login_required(login_url="/dashboard/")
def backup_logs(request, domain, jobid):
    base, headers, ca_cert = _load_k8s_auth()
    namespace = "kubepanel"
    ns_domain = domain.replace(".", "-")
    job_name  = f"backup-{ns_domain}-{jobid}"
    pods_url  = f"{base}/api/v1/namespaces/{namespace}/pods"
    params    = {"labelSelector": f"job-name={job_name}"}

    try:
        r = requests.get(pods_url, headers=headers, params=params,
                         verify=ca_cert, timeout=5)
        r.raise_for_status()
        items = r.json().get("items", [])
        if items:
            pod = items[0]
            pod_name = pod["metadata"]["name"]
            log_url  = (f"{base}/api/v1/namespaces/{namespace}"
                        f"/pods/{pod_name}/log")
            r2 = requests.get(log_url, headers=headers,
                              verify=ca_cert, timeout=10)
            if r2.status_code == 200:
                lines = r2.text.splitlines()
            else:
                lines = [f"Error {r2.status_code}: {r2.text}"]
            logs_by_container = {pod_name: lines}
            display_name = pod_name
        else:
            display_name = job_name
            logs_by_container = {}
    except Exception as e:
        display_name = job_name
        logs_by_container = {
            display_name: [f"Exception fetching logs: {e}"]
        }

    return render(request, "main/backup_logs.html", {
        "domain": domain,
        "namespace": namespace,
        "pod_name": display_name,
        "logs_by_container": logs_by_container,
    })


@login_required(login_url="/dashboard/")
def domain_logs(request, domain):
    domain_obj = get_object_or_404(Domain, domain_name=domain)
    ct = ContentType.objects.get_for_model(Domain)
    logs = (
        LogEntry.objects
        .filter(content_type=ct, object_id=domain_obj.pk)
        .order_by('-timestamp')
    )
    return render(request, 'main/domain_logs.html', {
        'domain': domain_obj.domain_name,
        'logs': logs,
    })


class PackageListView(SuperuserRequiredMixin, ListView):
    model = Package
    template_name = 'main/package_list.html'
    context_object_name = 'packages'

class PackageCreateView(SuperuserRequiredMixin, CreateView):
    model = Package
    form_class = PackageForm
    template_name = 'main/package_form.html'
    success_url = reverse_lazy('list_packages')

class PackageUpdateView(SuperuserRequiredMixin, UpdateView):
    model = Package
    form_class = PackageForm
    template_name = 'main/package_form.html'
    success_url = reverse_lazy('list_packages')

class UserProfileListView(SuperuserRequiredMixin, ListView):
    model = UserProfile
    template_name = 'main/userprofile_list.html'
    context_object_name = 'profiles'

class UserProfileCreateView(SuperuserRequiredMixin, CreateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'main/userprofile_form.html'
    success_url = reverse_lazy('list_userprofiles')

class UserProfileUpdateView(SuperuserRequiredMixin, UpdateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'main/userprofile_form.html'
    success_url = reverse_lazy('list_userprofiles')


class UserCreateView(SuperuserRequiredMixin, FormView):
    template_name = 'main/user_create.html'
    form_class = UserForm
    success_url = reverse_lazy('list_userprofiles')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['packages'] = Package.objects.all()
        return context

    def form_valid(self, form):
        user = form.save()
        pkg_id = self.request.POST.get('package')
        profile = UserProfile.objects.get(user=user)
        if pkg_id:
            profile.package_id = pkg_id
            profile.save()
        messages.success(self.request, 'User created successfully.')
        return super().form_valid(form)

class UserProfilePackageUpdateView(SuperuserRequiredMixin, UpdateView):
    model = UserProfile
    form_class = UserProfilePackageForm
    template_name = 'main/userprofile_edit.html'
    pk_url_kwarg = 'pk'
    success_url = reverse_lazy('list_userprofiles')

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['user'] = self.object.user
        return ctx

class DownloadSnapshotView(View):
    def get(self, request, snapshot_name):

        # Access control
        vs = get_object_or_404(Volumesnapshot, snapshotname=snapshot_name)
        if not request.user.is_superuser and vs.domain.owner != request.user:
            raise PermissionDenied
        # Load Kubernetes config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        # 2) Find a linstor-satellite pod & the full LV name
        pod_name = None
        lv_name  = None
        namespace = "piraeus-datastore"
        container = "linstor-satellite"
        snap_namespace = vs.domain.domain_name.replace(".","-")

        co_api = client.CustomObjectsApi()
        obj = co_api.get_namespaced_custom_object(
            group="snapshot.storage.k8s.io",
            version="v1",
            namespace=snap_namespace,
            plural="volumesnapshots",
            name=snapshot_name,
        )
        content_name = obj["status"]["boundVolumeSnapshotContentName"]
        # extract the UUID suffix after the first dash
        snap_id = content_name.split('-', 1)[1]
        v1 = client.CoreV1Api()
        pods = v1.list_namespaced_pod(
            namespace,
            label_selector="app.kubernetes.io/component=linstor-satellite"
        ).items

        for pod in pods:
            name = pod.metadata.name
            cmd_check = [
                "sh", "-c",
                f"lvs --noheadings -o lv_name linstorvg | grep {snap_id}"
            ]
            try:
                out = stream(
                    v1.connect_get_namespaced_pod_exec,
                    name=name,
                    namespace=namespace,
                    container=container,
                    command=cmd_check,
                    stderr=False, stdin=False, stdout=True, tty=False,
                ).strip()
            except ApiException:
                continue
            if out:
                pod_name = name
                lv_name  = out
                break

        if not pod_name or not lv_name:
            return HttpResponseNotFound(f"Snapshot {snapshot_name} not found")

        cmd = [
            "kubectl", "exec", "-i",
            "-n", namespace,
            pod_name, "-c", container,
            "--", "sh", "-c",
            f"thin_send linstorvg/{lv_name} | zstd -3 -c"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def stream_generator():
            for chunk in iter(lambda: proc.stdout.read(64*1024), b""):
                yield chunk
            code = proc.wait()
            if code != 0:
                err = proc.stderr.read().decode(errors="ignore")
                raise Exception(f"kubectl exec failed: {err}")

        response = StreamingHttpResponse(stream_generator(), content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{snapshot_name}.lv.zst"'
        return response

class DownloadSqlDumpView(View):
    def get(self, request, dump_name):
        # Access control: domain owner or superuser
        # dump_name is the VolumeSnapshot object name
        vs = get_object_or_404(Volumesnapshot, snapshotname=dump_name)
        if not request.user.is_superuser and vs.domain.owner != request.user:
            raise PermissionDenied

        # Load Kubernetes config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        namespace = "kubepanel"  # assuming PVC in domain namespace
        domain_name_dash = vs.domain.domain_name.replace(".","-")
        pvc_name = f"{domain_name_dash}-backup-pvc"
        file_path = f"/mnt/{dump_name}.sql"

        # 1) Create ephemeral pod manifest
        pod_body = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"generateName": f"backup-downloader-{domain_name_dash}-"},
            "spec": {
                "restartPolicy": "Never",
                "volumes": [{
                    "name": "backup-pvc",
                    "persistentVolumeClaim": {"claimName": pvc_name}
                }],
                "containers": [{
                    "name": "downloader",
                    "image": "alpine:latest",
                    "command": ["sh", "-c", f"sleep 3600"],
                    "volumeMounts": [{"mountPath": "/mnt", "name": "backup-pvc"}]
                }]
            }
        }
        v1 = client.CoreV1Api()
        pod = v1.create_namespaced_pod(namespace=namespace, body=pod_body)

        # 2) Wait for Pod to be running
        for _ in range(60):
            pod_status = v1.read_namespaced_pod(name=pod.metadata.name, namespace=namespace)
            if pod_status.status.phase == "Running":
                break
            time.sleep(1)
        else:
            v1.delete_namespaced_pod(name=pod.metadata.name, namespace=namespace)
            return HttpResponseNotFound("Failed to start helper pod")

        # 3) Stream the SQL file via cat
        cmd = ["cat", file_path]
        exec_stream = stream(
            v1.connect_get_namespaced_pod_exec,
            name=pod.metadata.name,
            namespace=namespace,
            container="downloader",
            command=cmd,
            stderr=True, stdin=False, stdout=True, tty=False,
            _preload_content=False
        )

        def generator():
            try:
                while exec_stream.is_open():
                    exec_stream.update(timeout=1)
                    chunk = exec_stream.read_stdout()
                    if chunk:
                        yield chunk
            finally:
                exec_stream.close()
                v1.delete_namespaced_pod(name=pod.metadata.name, namespace=namespace)

        response = StreamingHttpResponse(generator(), content_type="application/sql")
        response["Content-Disposition"] = (
            f'attachment; filename="{dump_name}.sql"'
        )
        return response

class UploadRestoreFilesView(View):
    """
    GET: render upload form
    POST: accept .lv.zst upload and queue for restore
    """
    def get(self, request, domain_name):
        # Access control
        domain = get_object_or_404(Domain, domain_name=domain_name)
        if not request.user.is_superuser and domain.owner != request.user:
            raise PermissionDenied
        return render(request, 'main/upload_snapshot.html', {
            'domain_name': domain_name
        })

    def post(self, request, domain_name):
        domain = get_object_or_404(Domain, domain_name=domain_name)
        if not request.user.is_superuser and domain.owner != request.user:
            raise PermissionDenied

        # Determine PVC name
        domain_name_dash = domain_name.replace(".","-")
        pvc_name = f"{domain_name_dash}-pvc"

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        try:
            pvc = v1.read_namespaced_persistent_volume_claim(
                name=pvc_name,
                namespace=domain_name_dash
            )
        except client.exceptions.ApiException:
            messages.error(request, f"PVC {pvc_name} not found in namespace {domain_name}.")
            return redirect(reverse('upload_restore', args=[domain_name]))

        pv_name = pvc.spec.volume_name

        # Ensure domain-specific directory exists
        domain_dir = os.path.join(UPLOAD_BASE_DIR, domain_name)
        os.makedirs(domain_dir, exist_ok=True)

        # Uploaded file
        snapshot_file = request.FILES.get('snapshot_file')
        if not snapshot_file:
            messages.error(request, 'No snapshot file provided.')
            return redirect(reverse('upload_restore', args=[domain_name]))

        filename = snapshot_file.name
        if not filename.endswith('.lv.zst'):
            messages.error(request, 'Invalid file type; must be .lv.zst')
            return redirect(reverse('upload_restore', args=[domain_name]))

        # Create job folder
        job_id = filename.rsplit('.', 2)[0]
        job_dir = os.path.join(domain_dir, job_id)
        os.makedirs(job_dir, exist_ok=True)

        # Save file
        dest_path = os.path.join(job_dir, filename)
        with open(dest_path, 'wb') as dest:
            for chunk in snapshot_file.chunks():
                dest.write(chunk)

        # Write PV name into READY semaphore
        ready_path = os.path.join(job_dir, 'READY')
        with open(ready_path, 'w') as sem:
            sem.write(pv_name)

        messages.success(request, 'Snapshot uploaded and queued for restore.')
        return redirect(reverse('upload_restore', args=[domain_name]))

def edit_dns_record(request, record_id):
    """Edit an existing DNS record"""
    logger.info(f"Starting edit_dns_record for record_id: {record_id}")

    try:
        record = get_object_or_404(DNSRecord, id=record_id)
        zone = record.zone
        logger.info(f"Found record: {record.record_type} {record.name} -> {record.content}")

    except Exception as e:
        logger.error(f"Error getting record: {e}")
        messages.error(request, f"Record not found: {e}")
        return redirect("zones_list")

    if request.method == "POST":
        logger.info("Processing POST request")
        logger.info(f"POST data: {dict(request.POST)}")

        # Create form with the existing record instance
        form = DNSRecordForm(request.POST, instance=record, user=request.user)

        # Remove zone from cleaned_data since we don't want to change it
        if form.is_valid():
            logger.info("Form is valid")
            logger.info(f"Form cleaned data: {form.cleaned_data}")

            try:
                # Get the updated data but don't save yet
                updated_record = form.save(commit=False)

                # Ensure the zone doesn't change (important!)
                updated_record.zone = record.zone
                updated_record.cf_record_id = record.cf_record_id  # Keep the CF record ID

                logger.info(f"Updated record prepared: {updated_record.record_type} {updated_record.name} -> {updated_record.content}")

                # Initialize Cloudflare service
                dns_service = CloudflareDNSService(record.zone.token.api_token)
                logger.info("Cloudflare service initialized")

                # Prepare update parameters for Cloudflare
                update_params = {
                    'zone_id': record.zone.zone_id,
                    'dns_record_id': record.cf_record_id,
                    'type': updated_record.record_type,
                    'name': updated_record.name,
                    'content': updated_record.content,
                    'ttl': updated_record.ttl,
                    'proxied': updated_record.proxied,
                }

                # Only add priority for record types that support it
                if updated_record.priority is not None and updated_record.record_type in ['MX', 'SRV']:
                    update_params['priority'] = updated_record.priority

                logger.info(f"Cloudflare update parameters: {update_params}")

                # Update in Cloudflare
                try:
                    logger.info("Attempting Cloudflare update...")
                    cf_response = dns_service._retry_api_call(
                        dns_service.client.dns.records.update,
                        **update_params
                    )
                    logger.info(f"Cloudflare update successful: {type(cf_response)}")

                except Exception as cf_error:
                    logger.error(f"Cloudflare update failed: {cf_error}")
                    logger.error(f"Error type: {type(cf_error)}")

                    # Try delete + create approach as fallback
                    logger.info("Trying delete + create approach...")

                    try:
                        # Delete old record
                        logger.info(f"Deleting old record: {record.cf_record_id}")
                        dns_service._retry_api_call(
                            dns_service.client.dns.records.delete,
                            zone_id=record.zone.zone_id,
                            dns_record_id=record.cf_record_id
                        )
                        logger.info("Old record deleted")

                        # Create new record
                        record_data = DNSRecordData(
                            record_type=updated_record.record_type,
                            name=updated_record.name,
                            content=updated_record.content,
                            ttl=updated_record.ttl,
                            proxied=updated_record.proxied,
                            priority=updated_record.priority
                        )
                        logger.info(f"Creating new record: {record_data}")

                        cf_record = dns_service.create_dns_record(record.zone.zone_id, record_data)
                        logger.info(f"New record created")

                        # Update the cf_record_id
                        record_id_new = cf_record.id if hasattr(cf_record, 'id') else cf_record.get('id')
                        updated_record.cf_record_id = record_id_new
                        logger.info(f"New Cloudflare record ID: {record_id_new}")

                    except Exception as fallback_error:
                        logger.error(f"Fallback approach failed: {fallback_error}")
                        raise fallback_error

                # Save to database
                logger.info("Saving to database...")
                with transaction.atomic():
                    updated_record.save()
                    logger.info("Database save successful")

                messages.success(request, "DNS record updated successfully.")
                logger.info("Edit completed successfully")
                return redirect("list_dns_records", zone_id=zone.id)

            except CloudflareAPIException as e:
                logger.error(f"CloudflareAPIException: {e}")
                messages.error(request, f"Cloudflare API error: {e.message}")

            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                messages.error(request, f"An unexpected error occurred: {str(e)}")

        else:
            logger.error(f"Form is not valid. Errors: {form.errors}")
            messages.error(request, "Please correct the form errors.")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        logger.info("GET request - displaying form")
        form = DNSRecordForm(instance=record, user=request.user)

    return render(request, "main/edit_dns_record.html", {
        "form": form,
        "record": record,
        "zone": zone,
    })


# Alternative: Simple database-only version for testing
def edit_dns_record_simple(request, record_id):
    """Simple version that only updates the database (for testing)"""
    logger.info(f"Simple edit for record_id: {record_id}")

    record = get_object_or_404(DNSRecord, id=record_id)
    zone = record.zone

    if request.method == "POST":
        logger.info(f"POST data: {dict(request.POST)}")

        # Manual field updates (bypass form for testing)
        try:
            record.record_type = request.POST.get('record_type', record.record_type)
            record.name = request.POST.get('name', record.name)
            record.content = request.POST.get('content', record.content)
            record.ttl = int(request.POST.get('ttl', record.ttl))
            record.proxied = 'proxied' in request.POST

            priority = request.POST.get('priority')
            if priority and priority.strip():
                record.priority = int(priority)
            elif record.record_type not in ['MX', 'SRV']:
                record.priority = None

            logger.info(f"About to save: {record.record_type} {record.name} -> {record.content}")
            record.save()
            logger.info("Database save successful")

            messages.success(request, "DNS record updated in database (simple mode).")
            return redirect("list_dns_records", zone_id=zone.id)

        except Exception as e:
            logger.error(f"Simple save error: {e}", exc_info=True)
            messages.error(request, f"Save error: {e}")

    context = {
        'record': record,
        'zone': zone,
        'record_types': DNSRecord.RECORD_TYPES,
    }

    return render(request, "main/test_edit_dns_record.html", context)
