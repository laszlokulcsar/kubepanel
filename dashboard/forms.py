from django import forms  
from django.contrib.auth.hashers import make_password
from dashboard.models import Domain, CloudflareAPIToken, DNSRecord, DNSZone, MailUser

class DomainForm(forms.ModelForm):
  class Meta:
    model = Domain
    fields = ["cpu_limit","mem_limit","nginx_config"]
    widgets = {
                'cpu_limit': forms.NumberInput(attrs={
                    'class': 'form-control',
                    'placeholder': 'CPU Limit in milliCPU',
                    'min': 100,
                    'max': 4000,
                }),
                'mem_limit': forms.NumberInput(attrs={
                    'class': 'form-control',
                    'min': 32,
                    'max': 4096,
                    'placeholder': 'Memory Limit in MiB'
                }),
                'nginx_config': forms.Textarea(attrs={
                    'class': 'form-control',
                }),
    }

class DomainAddForm(forms.ModelForm):
  class Meta:
    model = Domain
    fields = ["cpu_limit","mem_limit","storage_size"]
    widgets = {
                'cpu_limit': forms.NumberInput(attrs={
                    'class': 'form-control',
                    'placeholder': 'CPU Limit in milliCPU',
                    'min': 100,
                    'max': 4000,
                }),
                'mem_limit': forms.NumberInput(attrs={
                    'class': 'form-control',
                    'placeholder': 'Memory Limit in MiB',
                    'min': 32,
                    'max': 4096,
                }),
                'storage_size': forms.NumberInput(attrs={
                    'class': 'form-control',
                    'placeholder': 'Storage size in GiB',
                    'min': 1,
                    'max': 10000,
                }),
            }

class APITokenForm(forms.ModelForm):
    class Meta:
        model = CloudflareAPIToken
        fields = ["name", "api_token"]

class ZoneCreationForm(forms.Form):
    zone_name = forms.CharField(max_length=255)
    token = forms.ModelChoiceField(queryset=CloudflareAPIToken.objects.none())

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["token"].queryset = CloudflareAPIToken.objects.filter(user=user)

#  def __init__(self, *args, **kwargs):
#      super().__init__(*args, **kwargs)
#      # Mark scp_port as disabled (rendered as read-only)
#      self.fields['scp_port'].disabled = True

class DNSRecordForm(forms.ModelForm):
    class Meta:
        model = DNSRecord
        fields = ["zone", "record_type", "name", "content", "ttl", "proxied", "priority"]

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields["zone"].queryset = DNSZone.objects.filter(token__user=user)

class MailUserForm(forms.ModelForm):
    plain_password = forms.CharField(max_length=128, widget=forms.PasswordInput(), required=True)

    class Meta:
        model = MailUser
        fields = ['domain', 'local_part', 'plain_password', 'active']

    def save(self, commit=True):
        instance = super().save(commit=False)
        # Use SHA512 or other crypt scheme if you want direct Dovecot compatibility:
        # If you rely on Dovecot's "SHA512-CRYPT", you may need a custom hasher or call out to a library.
        #
        # For a quick fix, you can do:
        from passlib.hash import sha512_crypt
        hashed = sha512_crypt.using(rounds=5000).hash(self.cleaned_data['plain_password'])
        instance.password = hashed

        if commit:
            instance.save()
        return instance
