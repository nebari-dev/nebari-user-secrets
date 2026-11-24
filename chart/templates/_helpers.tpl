{{- define "user-secrets.labels" -}}
app.kubernetes.io/name: user-secrets
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "user-secrets.selectorLabels" -}}
app.kubernetes.io/name: user-secrets
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The rendered service config: the shape of internal/config Config. */}}
{{- define "user-secrets.config" -}}
namespace: {{ .Release.Namespace | quote }}
registry:
  apps: {{ .Values.registry.apps | default list | toJson }}
  creators: {{ .Values.registry.creators | default list | toJson }}
keycloak:
  jwksURL: {{ .Values.keycloak.jwksURL | quote }}
  issuers: {{ .Values.keycloak.issuers | toJson }}
  clientID: {{ .Values.keycloak.clientID | quote }}
tls:
  certFile: /etc/nebari/tls/tls.crt
  keyFile: /etc/nebari/tls/tls.key
guard:
  mode: {{ .Values.guard.mode | quote }}
limits: {{ .Values.limits | default dict | toJson }}
{{- $k := .Values.kubernetes | default dict }}
kubernetes:
  qps: {{ $k.qps | default 0 | float64 }}
  burst: {{ $k.burst | default 0 | int64 }}
initImage: {{ .Values.initImage | default .Values.image | quote }}
{{- end -}}

{{/* The registered workload namespaces, unique and sorted, as a JSON list. */}}
{{- define "user-secrets.workloadNamespaces" -}}
{{- $ns := list -}}
{{- range .Values.registry.apps | default list -}}
  {{- range .workloads | default list -}}
    {{- $ns = append $ns .namespace -}}
  {{- end -}}
{{- end -}}
{{- $ns | uniq | sortAlpha | toJson -}}
{{- end -}}
