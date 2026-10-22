{{- define "allowops.name" -}}
{{- printf "%s-allowops" .Release.Name | trunc 54 | trimSuffix "-" -}}
{{- end -}}

{{- define "allowops.labels" -}}
app.kubernetes.io/name: allowops
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "allowops.config" -}}
address: ':8443'
tls_certificate: /run/allowops/credentials/tls.crt
tls_key: /run/allowops/credentials/tls.key
ca_certificate: /run/allowops/credentials/ca.crt
ca_key: /run/allowops/credentials/ca.key
catalog_keys: /run/allowops/credentials/catalog-keys
output:
  bucket: {{ .Values.output.bucket | quote }}
  region: {{ .Values.output.region | quote }}
  endpoint: {{ .Values.output.endpoint | quote }}
gateway:
  shutdown_grace: {{ printf "%ds" (int .Values.gateway.shutdownGraceSeconds) | quote }}
management:
{{ toYaml .Values.gateway.management | indent 2 }}
identity:
{{ toYaml .Values.gateway.identity | indent 2 }}
providers:
{{ toYaml .Values.gateway.providers | indent 2 }}
{{- end -}}

{{- define "allowops.pod" -}}
automountServiceAccountToken: false
nodeSelector:
  kubernetes.io/arch: amd64
  kubernetes.io/os: linux
terminationGracePeriodSeconds: {{ add .Values.gateway.shutdownGraceSeconds 10 }}
securityContext:
  runAsUser: 65532
  runAsGroup: 65532
  runAsNonRoot: true
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
initContainers:
  - name: copy-secrets
    image: {{ .Values.secretCopyImage | quote }}
    command: ["/bin/sh", "-ec"]
    args:
      - |
        mkdir -p /run/allowops/credentials/catalog-keys
        cp /secret/ca.crt /secret/ca.key /secret/tls.crt /secret/tls.key /run/allowops/credentials/
        cp /audit-secret/audit-cursor-key /run/allowops/credentials/audit-cursor-key
        cp /output-secret/aws-credentials /run/allowops/credentials/aws-credentials
        cp /secret/catalog.pub.pem /run/allowops/credentials/catalog-keys/
        chmod 0700 /run/allowops/credentials /run/allowops/credentials/catalog-keys
        chmod 0600 /run/allowops/credentials/audit-cursor-key /run/allowops/credentials/aws-credentials /run/allowops/credentials/ca.crt /run/allowops/credentials/ca.key /run/allowops/credentials/tls.crt /run/allowops/credentials/tls.key /run/allowops/credentials/catalog-keys/catalog.pub.pem
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
    volumeMounts:
      - name: secret
        mountPath: /secret
        readOnly: true
      - name: audit-secret
        mountPath: /audit-secret
        readOnly: true
      - name: output-secret
        mountPath: /output-secret
        readOnly: true
      - name: credentials
        mountPath: /run/allowops
containers:
  - name: gateway
    image: {{ printf "%s:%s" .Values.image.repository .Values.image.tag | quote }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    args: [serve, --config, /etc/allowops/{{ .configFile }}]
    env:
      - name: AWS_SHARED_CREDENTIALS_FILE
        value: /run/allowops/credentials/aws-credentials
      - name: AWS_EC2_METADATA_DISABLED
        value: "true"
      - name: ALLOWOPS_DATABASE_URL
        valueFrom:
          secretKeyRef:
            name: {{ .Values.database.existingSecret }}
            key: {{ .Values.database.key }}
    ports:
      - name: tls
        containerPort: 8443
    startupProbe:
      httpGet:
        scheme: HTTPS
        path: /health/live
        port: tls
      timeoutSeconds: 5
      failureThreshold: 30
      periodSeconds: 2
    readinessProbe:
      httpGet:
        scheme: HTTPS
        path: /health/ready
        port: tls
      timeoutSeconds: 5
      periodSeconds: 5
    livenessProbe:
      httpGet:
        scheme: HTTPS
        path: /health/live
        port: tls
      timeoutSeconds: 5
      periodSeconds: 10
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
    resources:
{{ toYaml .Values.resources | indent 6 }}
    volumeMounts:
      - name: config
        mountPath: /etc/allowops
        readOnly: true
      - name: credentials
        mountPath: /run/allowops
        readOnly: true
      {{- if .exporter }}
      - name: audit
        mountPath: /var/lib/allowops/audit
      {{- end }}
volumes:
  - name: config
    configMap:
      name: {{ include "allowops.name" . }}
  - name: secret
    secret:
      secretName: {{ .Values.credentials.existingSecret }}
      defaultMode: 0440
  - name: audit-secret
    secret:
      secretName: {{ .Values.audit.cursorKeySecret }}
      defaultMode: 0440
      items:
        - key: {{ .Values.audit.cursorKeyKey | quote }}
          path: audit-cursor-key
  - name: output-secret
    secret:
      secretName: {{ .Values.output.existingSecret }}
      defaultMode: 0440
      items:
        - key: {{ .Values.output.credentialsKey | quote }}
          path: aws-credentials
  - name: credentials
    emptyDir:
      medium: Memory
{{- end -}}
