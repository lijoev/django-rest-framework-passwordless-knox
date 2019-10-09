from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class DrfpasswordlessConfig(AppConfig):
    name = 'knoxpasswordlessdrf'
    verbose = _("DRF Passwordless")

    def ready(self):
        import knoxpasswordlessdrf.signals
