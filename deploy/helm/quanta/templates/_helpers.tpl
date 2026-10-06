{{/* Names and labels */}}
{{- define "quanta.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "quanta.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "quanta.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "quanta.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "quanta.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quanta.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "quanta.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "quanta.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "quanta.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Secrets */}}
{{- define "quanta.secretKeys" -}}
{{- concat .Values.secrets.keys .Values.secrets.optionalKeys | uniq | toJson -}}
{{- end -}}

{{/* The vault entry name for a setting: keyMap entry, else the setting name itself */}}
{{- define "quanta.vaultName" -}}
{{- $root := index . 0 -}}
{{- $key := index . 1 -}}
{{- default $key (index $root.Values.secrets.keyMap $key) -}}
{{- end -}}

{{/* The Kubernetes Secret that holds the values, for the modes that use one */}}
{{- define "quanta.secretName" -}}
{{- if eq .Values.secrets.mode "existingSecret" -}}
{{- required "secrets.existingSecret is required when secrets.mode is existingSecret" .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "quanta.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* CSI SecretProviderClass name */}}
{{- define "quanta.spcName" -}}
{{- printf "%s-vault" (include "quanta.fullname" .) -}}
{{- end -}}

{{/* Refuse unsafe or incomplete configurations at render time */}}
{{- define "quanta.validate" -}}
{{- if and .Values.web.trustForwardedHeaders (not .Values.networkPolicy.enabled) -}}
{{- fail "web.trustForwardedHeaders=true is only safe with networkPolicy.enabled=true: without it any pod in the cluster can reach the web pods directly and forge X-Forwarded-For. Enable networkPolicy or leave trustForwardedHeaders false." -}}
{{- end -}}
{{- $modes := list "externalSecrets" "csi" "existingSecret" "inline" -}}
{{- if not (has .Values.secrets.mode $modes) -}}
{{- fail (printf "secrets.mode must be one of %s" (join ", " $modes)) -}}
{{- end -}}
{{- if and (eq .Values.secrets.mode "inline") (not .Values.secrets.allowInline) -}}
{{- fail "secrets.mode=inline puts secrets in your values file and Helm release history. Use externalSecrets or csi with a key vault, or set secrets.allowInline=true for a throwaway development install." -}}
{{- end -}}
{{- if and (eq .Values.secrets.mode "externalSecrets") (not .Values.secrets.externalSecrets.secretStoreRef.name) -}}
{{- fail "secrets.externalSecrets.secretStoreRef.name is required: the (Cluster)SecretStore that points at your key vault" -}}
{{- end -}}
{{- if and (eq .Values.secrets.mode "csi") (eq .Values.secrets.csi.provider "azure") (not .Values.secrets.csi.azure.keyvaultName) -}}
{{- fail "secrets.csi.azure.keyvaultName is required" -}}
{{- end -}}
{{- $replicated := or (gt (int .Values.web.replicas) 1) .Values.web.autoscaling.enabled (and .Values.worker.enabled (gt (int .Values.worker.replicas) 1)) .Values.worker.autoscaling.enabled -}}
{{- if not (has .Values.files.backend (list "db" "volume")) -}}
{{- fail "files.backend must be db or volume" -}}
{{- end -}}
{{- if and $replicated (eq .Values.files.backend "volume") (not .Values.persistence.enabled) -}}
{{- fail "files.backend=volume with more than one replica needs persistence.enabled=true and a ReadWriteMany volume, or use files.backend=db (the default). See docs/KUBERNETES.md." -}}
{{- end -}}
{{- if and $replicated (eq .Values.files.backend "volume") .Values.persistence.enabled (not .Values.persistence.existingClaim) (not (has "ReadWriteMany" .Values.persistence.accessModes)) -}}
{{- fail "persistence.accessModes must include ReadWriteMany when there is more than one replica" -}}
{{- end -}}
{{- if and $replicated (ne .Values.coordination.lockBackend "db") -}}
{{- fail "coordination.lockBackend must be db when there is more than one replica: file locks do not work across pods" -}}
{{- end -}}
{{- end -}}

{{/* Environment shared by every Quanta container (never a secret value; secrets are *_FILE paths) */}}
{{- define "quanta.env" -}}
- name: QUANTA_PRODUCTION
  value: {{ .Values.config.production | quote }}
- name: QUANTA_HOST
  value: "0.0.0.0"
- name: QUANTA_PORT
  value: {{ .Values.web.port | quote }}
- name: QUANTA_DISABLE_TLS
  value: "true"
- name: QUANTA_LOG_FORMAT
  value: {{ .Values.config.logFormat | quote }}
- name: QUANTA_LOCK_BACKEND
  value: {{ .Values.coordination.lockBackend | quote }}
- name: QUANTA_FILES_BACKEND
  value: {{ .Values.files.backend | quote }}
- name: QUANTA_FILES_SYNC_SECONDS
  value: {{ .Values.files.syncSeconds | quote }}
- name: QUANTA_LEADER_TTL_SECONDS
  value: {{ .Values.config.leaderTtlSeconds | quote }}
- name: QUANTA_GITOPS_SYNC
  value: {{ .Values.config.gitopsSync | quote }}
- name: QUANTA_JOB_VISIBILITY_SECONDS
  value: {{ .Values.worker.jobVisibilitySeconds | quote }}
{{- if .Values.config.bootstrapAdminEmail }}
- name: QUANTA_BOOTSTRAP_ADMIN_EMAIL
  value: {{ .Values.config.bootstrapAdminEmail | quote }}
{{- end }}
{{- if .Values.config.supportEmail }}
- name: QUANTA_SUPPORT_EMAIL
  value: {{ .Values.config.supportEmail | quote }}
{{- end }}
{{- if .Values.config.smtp.host }}
- name: SMTP_HOST
  value: {{ .Values.config.smtp.host | quote }}
- name: SMTP_PORT
  value: {{ .Values.config.smtp.port | quote }}
- name: SMTP_FROM_ADDRESS
  value: {{ .Values.config.smtp.fromAddress | quote }}
{{- end }}
{{- range $key := (include "quanta.secretKeys" . | fromJsonArray) }}
- name: {{ $key }}_FILE
  value: {{ printf "%s/%s" $.Values.secrets.mountPath $key | quote }}
{{- end }}
{{- with .Values.config.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Volumes: the vault secrets, plus the shared volume when enabled */}}
{{- define "quanta.volumes" -}}
- name: quanta-secrets
{{- if eq .Values.secrets.mode "csi" }}
  csi:
    driver: secrets-store.csi.k8s.io
    readOnly: true
    volumeAttributes:
      secretProviderClass: {{ include "quanta.spcName" . }}
{{- else }}
  secret:
    secretName: {{ include "quanta.secretName" . }}
    defaultMode: 0440
    items:
    {{- range $key := (include "quanta.secretKeys" . | fromJsonArray) }}
      - key: {{ $key }}
        path: {{ $key }}
    {{- end }}
{{- end }}
{{- if and .Values.persistence.enabled (eq .Values.files.backend "volume") }}
- name: quanta-data
  persistentVolumeClaim:
    claimName: {{ default (printf "%s-data" (include "quanta.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}
{{- end -}}

{{- define "quanta.volumeMounts" -}}
- name: quanta-secrets
  mountPath: {{ .Values.secrets.mountPath }}
  readOnly: true
{{- if and .Values.persistence.enabled (eq .Values.files.backend "volume") }}
- name: quanta-data
  mountPath: /app/remediation/output
  subPath: output
- name: quanta-data
  mountPath: /app/remediation/live-data
  subPath: live-data
- name: quanta-data
  mountPath: /app/remediation/config
  subPath: config
{{- end }}
{{- end -}}

{{- define "quanta.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.securityContext.runAsUser }}
runAsGroup: {{ .Values.securityContext.runAsGroup }}
fsGroup: {{ .Values.securityContext.fsGroup }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "quanta.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
{{- if .Values.containerSecurityContext.readOnlyRootFilesystem }}
readOnlyRootFilesystem: true
{{- end }}
{{- end -}}

{{/* Init containers: seed the shared config volume once, then create the schema / first admin exactly once */}}
{{- define "quanta.initContainers" -}}
{{- if and .Values.persistence.enabled (eq .Values.files.backend "volume") }}
- name: seed-config
  image: {{ include "quanta.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  # The shared volume starts empty and would hide the policy files baked into the image, so copy
  # them in once. -n never overwrites a file an administrator has edited.
  command: ["sh", "-c", "mkdir -p /data/output /data/live-data /data/config && (cp -rn /app/remediation/config/. /data/config/ || true)"]
  securityContext:
    {{- include "quanta.containerSecurityContext" . | nindent 4 }}
  volumeMounts:
    - name: quanta-data
      mountPath: /data
{{- end }}
- name: prepare
  image: {{ include "quanta.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  # Schema, sample-data clean-up and the first admin run once for the whole release: a lease in the
  # database makes the other replicas' init containers wait for the first to finish.
  command: ["python", "cli/quanta_admin.py", "prepare"]
  env:
    {{- include "quanta.env" . | nindent 4 }}
  securityContext:
    {{- include "quanta.containerSecurityContext" . | nindent 4 }}
  volumeMounts:
    {{- include "quanta.volumeMounts" . | nindent 4 }}
{{- end -}}
