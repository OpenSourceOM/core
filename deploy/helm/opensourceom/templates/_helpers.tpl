{{/*
Copyright 2026 OpenSourceOM
SPDX-License-Identifier: Apache-2.0
*/}}
{{- define "opensourceom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "opensourceom.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "opensourceom.labels" -}}
app.kubernetes.io/name: {{ include "opensourceom.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "opensourceom.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{- define "opensourceom.dbEnv" -}}
- name: POSTGRES_USER
  value: {{ .Values.postgres.user | quote }}
- name: POSTGRES_DB
  value: {{ .Values.postgres.database | quote }}
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_HOST
  value: {{ if .Values.postgres.enabled }}{{ printf "%s-postgres" (include "opensourceom.fullname" .) | quote }}{{ else }}{{ required "postgres.host is required when postgres.enabled is false" .Values.postgres.host | quote }}{{ end }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "opensourceom.fullname" . }}
      key: POSTGRES_PASSWORD
{{- end }}
