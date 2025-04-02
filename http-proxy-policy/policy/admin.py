# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from django import forms
from django.contrib import admin, messages
from django.db import transaction
from django.shortcuts import redirect
from django.urls import path

import policy.engine as engine
import policy.models as models
from policy.models import Verdict


class RuleAdminForm(forms.ModelForm):
    requirer = forms.CharField(
        required=False, help_text="Match requirer id. Leave empty to match all."
    )
    domains = forms.CharField(
        required=False,
        widget=forms.Textarea,
        help_text="Match domains: a comma-separated list of host[:port]. Leave empty to match all.",
    )
    auth = forms.MultipleChoiceField(
        required=False,
        choices={auth: auth for auth in models.AUTH_METHODS},
        widget=forms.CheckboxSelectMultiple,
        help_text="Match authentication methods. Leave empty to match all.",
    )
    src_ips = forms.CharField(
        required=False,
        widget=forms.Textarea,
        help_text="Match source IPs, a comma-separated list of IPv4 or IPv6 networks. Leave empty to match all.",
    )
    verdict = forms.ChoiceField(
        required=True,
        choices={verdict: verdict for verdict in Verdict},
    )
    comment = forms.CharField(required=False, widget=forms.Textarea, help_text="Comment")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.instance and self.instance.pk:
            self.initial["domains"] = (
                ", ".join(models.compact_domains(self.instance.domains))
                if self.instance.domains
                else ""
            )
            self.initial["src_ips"] = (
                ", ".join(models.compact_domains(self.instance.src_ips.source))
                if self.instance.src_ips.source
                else ""
            )
            self.initial["verdict"] = self.instance.verdict

    class Meta:
        model = models.Rule
        fields = "__all__"

    def clean_requirer(self):
        data = self.cleaned_data.get("requirer")
        if not data:
            return None
        return data

    def clean_domains(self):
        data = self.cleaned_data.get("domains", "")
        return [d.strip() for d in data.split(",") if d.strip()] if data else []

    def clean_src_ips(self):
        data = self.cleaned_data.get("src_ips", "")
        return [ip.strip() for ip in data.split(",") if ip.strip()] if data else []

    def clean(self):
        cleaned_data = super().clean()
        try:
            validated = models.RuleInput(**cleaned_data)
        except ValueError as e:
            raise forms.ValidationError(str(e))
        return validated.model_dump()


@admin.register(models.Rule)
class RuleAdmin(admin.ModelAdmin):
    form = RuleAdminForm

    list_display = (
        "id",
        "get_requirer",
        "get_domains",
        "get_auth",
        "get_src_ips",
        "verdict",
        "comment",
    )
    search_fields = ("requirer", "domains", "comment")

    def get_requirer(self, obj):
        return str(obj.requirer) if obj.requirer else "*"

    get_requirer.short_description = "Requirer"

    def get_domains(self, obj):
        return ", ".join(models.compact_domains(obj.domains)) if obj.domains else "*"

    get_domains.short_description = "Domains"

    def get_auth(self, obj):
        return ", ".join(obj.auth) if obj.auth else "*"

    get_auth.short_description = "Auth"

    def get_src_ips(self, obj):
        return ", ".join(obj.src_ips.source) if obj.src_ips.source else "*"

    get_src_ips.short_description = "Src IP networks"

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            super().save_model(request, obj, form, change)

    def delete_model(self, request, obj):
        with transaction.atomic():
            super().delete_model(request, obj)


@admin.register(models.Request)
class RequestAdmin(admin.ModelAdmin):
    change_form_template = "policy/request_change_form.html"

    list_display = (
        "requirer",
        "get_domains",
        "get_auth",
        "get_src_ips",
        "get_status",
        "accepted_auth",
    )
    search_fields = ("requirer", "domains")
    list_filter = ("status",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_domains(self, obj):
        return ", ".join(models.compact_domains(obj.domains)) if obj.domains else "-"

    get_domains.short_description = "Domains"

    def get_auth(self, obj):
        return ", ".join(obj.auth) if obj.auth else "-"

    get_auth.short_description = "Requested Auth"

    def get_src_ips(self, obj):
        return ", ".join(obj.src_ips.source) if obj.src_ips.source else "-"

    get_src_ips.short_description = "Src IPs"

    def get_status(self, obj):
        if obj.status != models.PROXY_STATUS_PENDING:
            count = models.Rule.objects.filter(requirer=obj.requirer).count()
            if count == 0:
                return f"automatically {obj.status}"
        return obj.status

    get_status.short_description = "Status"

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "accept-proxy-request/<uuid:pk>",
                self.admin_site.admin_view(self.accept_proxy_request),
                name="accept-proxy-request",
            ),
            path(
                "reject-proxy-request/<uuid:pk>",
                self.admin_site.admin_view(self.reject_proxy_request),
                name="reject-proxy-request",
            ),
        ]
        return custom_urls + urls

    def accept_proxy_request(self, request, pk):
        try:
            proxy_request = models.Request.objects.get(pk=pk)
        except models.Request.DoesNotExist:
            self.message_user(request, f"request {pk} does not exist", level=messages.ERROR)
            return redirect(request.META.get("HTTP_REFERER", "/"))
        with transaction.atomic():
            models.Rule.objects.filter(requirer=proxy_request.requirer).delete()
            engine.make_rule(request=proxy_request, verdict=models.Verdict.ACCEPT).save()
        self.message_user(request, f"accept request {pk}!", messages.SUCCESS)
        return redirect(request.META.get("HTTP_REFERER", "/"))

    def reject_proxy_request(self, request, pk):
        try:
            proxy_request = models.Request.objects.get(pk=pk)
        except models.Request.DoesNotExist:
            self.message_user(request, f"request {pk} does not exist", level=messages.ERROR)
            return redirect(request.META.get("HTTP_REFERER", "/"))
        with transaction.atomic():
            models.Rule.objects.filter(requirer=proxy_request.requirer).delete()
            engine.make_rule(request=proxy_request, verdict=models.Verdict.REJECT).save()
        self.message_user(request, f"reject request {pk}!", messages.SUCCESS)
        return redirect(request.META.get("HTTP_REFERER", "/"))
