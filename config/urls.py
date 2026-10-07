from django.contrib import admin
from django.urls import path

admin.site.site_header = "Rejestr certyfikatów (DORA)"
admin.site.site_title = "Rejestr certyfikatów"
admin.site.index_title = "Zarządzanie certyfikatami X.509/TLS"

urlpatterns = [path("", admin.site.urls)]
