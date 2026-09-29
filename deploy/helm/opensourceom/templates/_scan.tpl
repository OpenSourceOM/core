{{/*
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
*/}}
{{- define "opensourceom.scan.serviceAccountName" -}}
{{- printf "%s-scan" (include "opensourceom.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "opensourceom.scan.inlineSecretName" -}}
{{- printf "%s-scan-creds" (include "opensourceom.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "opensourceom.scan.secretEnv" -}}
{{- $secret := .name -}}
{{- range .keys }}
- name: {{ . }}
  valueFrom:
    secretKeyRef:
      name: {{ $secret | quote }}
      key: {{ . }}
{{- end }}
{{- end -}}

{{- define "opensourceom.scan.jobName" -}}
{{- printf "%s-scan-%s" (include "opensourceom.fullname" .root) .suffix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "opensourceom.scan.aws.on" -}}
{{- $keys := and .Values.scan.aws.accessKeyId .Values.scan.aws.secretAccessKey -}}
{{- if and .Values.scan.aws.enabled (or .Values.scan.aws.existingSecret $keys .Values.scan.aws.serviceAccountAuth) -}}
true
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.aws.envFrom" -}}
{{- if .Values.scan.aws.existingSecret -}}
{{- .Values.scan.aws.existingSecret -}}
{{- else if and .Values.scan.aws.accessKeyId .Values.scan.aws.secretAccessKey -}}
{{- include "opensourceom.scan.inlineSecretName" . -}}
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.azure.on" -}}
{{- $keys := and .Values.scan.azure.tenantId .Values.scan.azure.clientId .Values.scan.azure.clientSecret -}}
{{- if and .Values.scan.azure.enabled .Values.scan.azure.subscriptionId (or .Values.scan.azure.existingSecret $keys .Values.scan.azure.serviceAccountAuth) -}}
true
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.azure.envFrom" -}}
{{- if .Values.scan.azure.existingSecret -}}
{{- .Values.scan.azure.existingSecret -}}
{{- else if and .Values.scan.azure.tenantId .Values.scan.azure.clientId .Values.scan.azure.clientSecret -}}
{{- include "opensourceom.scan.inlineSecretName" . -}}
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.gcp.on" -}}
{{- if and .Values.scan.gcp.enabled .Values.scan.gcp.projectId (or .Values.scan.gcp.existingSecret .Values.scan.gcp.credentialsJson .Values.scan.gcp.serviceAccountAuth) -}}
true
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.gcp.secretName" -}}
{{- if .Values.scan.gcp.existingSecret -}}
{{- .Values.scan.gcp.existingSecret -}}
{{- else if .Values.scan.gcp.credentialsJson -}}
{{- include "opensourceom.scan.inlineSecretName" . -}}
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.k8s.on" -}}
{{- if .Values.scan.kubernetes.enabled -}}
true
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.k8s.inCluster" -}}
{{- if and (eq (include "opensourceom.scan.k8s.on" .) "true") (not .Values.scan.kubernetes.existingSecret) -}}
true
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.any" -}}
{{- if or (eq (include "opensourceom.scan.aws.on" .) "true") (eq (include "opensourceom.scan.azure.on" .) "true") (eq (include "opensourceom.scan.gcp.on" .) "true") (eq (include "opensourceom.scan.k8s.on" .) "true") -}}
true
{{- end -}}
{{- end -}}

{{- define "opensourceom.scan.inline" -}}
{{- if or (eq (include "opensourceom.scan.aws.envFrom" .) (include "opensourceom.scan.inlineSecretName" .)) (eq (include "opensourceom.scan.azure.envFrom" .) (include "opensourceom.scan.inlineSecretName" .)) (eq (include "opensourceom.scan.gcp.secretName" .) (include "opensourceom.scan.inlineSecretName" .)) -}}
true
{{- end -}}
{{- end -}}

{{/*
CronJob for one collector. .root is the chart context. Overlapping runs are
forbidden so ReplaceInventory for one account does not race itself.
*/}}
{{- define "opensourceom.scan.cronjob" -}}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ .name }}
  labels:
    {{- include "opensourceom.labels" .root | nindent 4 }}
    app.kubernetes.io/component: scan
spec:
  schedule: {{ .root.Values.scan.schedule | quote }}
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: {{ .root.Values.scan.successfulJobsHistoryLimit }}
  failedJobsHistoryLimit: {{ .root.Values.scan.failedJobsHistoryLimit }}
  jobTemplate:
    spec:
      backoffLimit: 2
      activeDeadlineSeconds: {{ .root.Values.scan.activeDeadlineSeconds }}
      template:
        metadata:
          labels:
            {{- include "opensourceom.labels" .root | nindent 12 }}
            app.kubernetes.io/component: scan
        spec:
          restartPolicy: OnFailure
          serviceAccountName: {{ include "opensourceom.scan.serviceAccountName" .root }}
          automountServiceAccountToken: {{ .automountToken }}
          initContainers:
            - name: wait-db
              image: {{ .root.Values.postgres.image }}
              command: ["sh", "-c", "until pg_isready -h \"$POSTGRES_HOST\" -U \"$POSTGRES_USER\"; do sleep 2; done"]
              env:
                {{- include "opensourceom.dbEnv" .root | nindent 16 }}
          containers:
            - name: scan
              image: {{ include "opensourceom.image" .root }}
              imagePullPolicy: {{ .root.Values.image.pullPolicy }}
              args:
                {{- toYaml .args | nindent 16 }}
              env:
                {{- with .extraEnv }}
                {{- . | nindent 16 }}
                {{- end }}
                {{- include "opensourceom.dbEnv" .root | nindent 16 }}
              {{- with .volumeMounts }}
              volumeMounts:
                {{- . | nindent 16 }}
              {{- end }}
              resources:
                {{- if .root.Values.scan.resources }}
                {{- toYaml .root.Values.scan.resources | nindent 16 }}
                {{- else }}
                {{- toYaml .root.Values.resources | nindent 16 }}
                {{- end }}
          {{- with .volumes }}
          volumes:
            {{- . | nindent 12 }}
          {{- end }}
{{- end -}}
