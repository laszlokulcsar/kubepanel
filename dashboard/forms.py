from django import forms  
from dashboard.models import Domains

class DomainForm(forms.ModelForm):
  class Meta:
    model = Domains
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
    model = Domains
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


#  def __init__(self, *args, **kwargs):
#      super().__init__(*args, **kwargs)
#      # Mark scp_port as disabled (rendered as read-only)
#      self.fields['scp_port'].disabled = True
