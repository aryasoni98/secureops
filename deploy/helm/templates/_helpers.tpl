{{- define "secureops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "secureops.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "secureops.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "secureops.labels" -}}
app.kubernetes.io/name: {{ include "secureops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: secureops
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "secureops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secureops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end -}}
