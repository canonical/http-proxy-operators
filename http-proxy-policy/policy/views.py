# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotFound, HttpResponse
from rest_framework import permissions
from rest_framework.views import APIView

import policy.models as models
import policy.engine as engine
from policy.transaction import serializable_isolation_transaction


class RefreshRequestsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return HttpResponseBadRequest("invalid JSON")

        if not isinstance(data, list):
            return HttpResponseBadRequest(f"not a list: {data}")

        new_requests = {}

        for proxy_request in data:
            if not isinstance(proxy_request, dict):
                return HttpResponseBadRequest(f"not a json object: {proxy_request}")

            requirer = proxy_request.get("requirer")
            if requirer is None:
                return HttpResponseBadRequest(f"missing requirer field: {proxy_request}")

            if requirer in new_requests:
                return HttpResponseBadRequest(f"duplicate requirer: {requirer}")

            try:
                validated_request = models.RequestInput(**proxy_request)
            except ValueError as e:
                return HttpResponseBadRequest(str(e))

            new_requests[validated_request.requirer] = models.Request(
                requirer=validated_request.requirer,
                domains=validated_request.domains,
                auth=validated_request.auth,
                src_ips=models.IpSet(list(validated_request.src_ips)),
                implicit_src_ips=validated_request.implicit_src_ips,
            )

        with serializable_isolation_transaction():
            rules = list(models.Rule.objects.all())
            for model_request in new_requests.values():
                engine.apply_rules(rules=rules, request=model_request)
                model_request.save()
            models.Request.objects.exclude(requirer__in=new_requests.keys()).delete()

        return JsonResponse([r.to_jsonable() for r in new_requests.values()], safe=False)


class AcceptRequestsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            proxy_request = models.Request.objects.get(pk=pk)
        except models.Request.DoesNotExist:
            return HttpResponseNotFound()
        with serializable_isolation_transaction():
            models.Rule.objects.filter(requirer=proxy_request.requirer).delete()
            engine.make_rule(request=proxy_request, verdict=models.Verdict.ACCEPT).save()
        return HttpResponse()


class RejectRequestsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            proxy_request = models.Request.objects.get(pk=pk)
        except models.Request.DoesNotExist:
            return HttpResponseNotFound()
        with serializable_isolation_transaction():
            models.Rule.objects.filter(requirer=proxy_request.requirer).delete()
            engine.make_rule(request=proxy_request, verdict=models.Verdict.REJECT).save()
        return HttpResponse()


class GetRequestsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            proxy_request = models.Request.objects.get(pk=pk)
        except models.Request.DoesNotExist:
            return HttpResponseNotFound()
        return JsonResponse(proxy_request.to_jsonable())


class ListRequestsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = request.GET.get("status")
        if status:
            proxy_requests = models.Request.objects.filter(status=status)
        else:
            proxy_requests = models.Request.objects.all()
        return JsonResponse([r.to_jsonable() for r in proxy_requests], safe=False)


class ListCreateRulesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        rules = models.Rule.objects.all()
        return JsonResponse([r.to_jsonable() for r in rules], safe=False)

    def put(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return HttpResponseBadRequest("invalid JSON")

        if not isinstance(data, dict):
            return HttpResponseBadRequest(f"not a dict: {data}")

        try:
            validated = models.RuleInput(**data)
        except ValueError as e:
            return HttpResponseBadRequest(str(e))
        with serializable_isolation_transaction():
            rule = models.Rule.objects.create(
                requirer=validated.requirer,
                domains=validated.domains,
                auth=validated.auth,
                src_ips=validated.src_ips,
                verdict=validated.verdict,
                comment=validated.comment,
            )
            rule = models.Rule.objects.get(pk=rule.pk)
        return JsonResponse(rule.to_jsonable())


class RuleApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            rule = models.Rule.objects.get(pk=pk)
        except models.Rule.DoesNotExist:
            return HttpResponseNotFound()
        return JsonResponse(rule.to_jsonable())

    def delete(self, request, pk):
        try:
            models.Rule.objects.filter(pk=pk).delete()
        except models.Rule.DoesNotExist:
            pass

    def patch(self, request, pk):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return HttpResponseBadRequest("invalid JSON")

        if not isinstance(data, dict):
            return HttpResponseBadRequest(f"not a dict: {data}")

        data["id"] = pk

        try:
            validated = models.RuleInput(**data)
        except ValueError as e:
            return HttpResponseBadRequest(str(e))

        with serializable_isolation_transaction():
            try:
                rule = models.Rule.objects.get(pk=pk)
            except models.Rule.DoesNotExist:
                return HttpResponseNotFound()
            rule.requirer = validated.requirer
            rule.domains = validated.domains
            rule.auth = validated.auth
            rule.src_ips = validated.src_ips
            rule.verdict = validated.verdict
            rule.comment = validated.comment
            rule.save()
