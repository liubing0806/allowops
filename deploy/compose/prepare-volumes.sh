#!/bin/sh
set -eu
mkdir -p /credentials/catalog-keys
cp /source/secrets/host-ca.crt /credentials/ca.crt
cp /source/secrets/host-ca.key /credentials/ca.key
cp /source/secrets/audit-cursor-key /source/secrets/aws-credentials /source/secrets/tls-ca.crt /credentials/
cp /source/secrets/tls.crt /credentials/tls.crt
cp /source/secrets/tls.key /credentials/tls.key
cp /source/secrets/catalog.pub.pem /credentials/catalog-keys/catalog.pub.pem
chown -R 65532:65532 /credentials /audit
chmod 0700 /credentials /credentials/catalog-keys /audit
chmod 0600 /credentials/audit-cursor-key /credentials/aws-credentials /credentials/tls-ca.crt /credentials/ca.crt /credentials/ca.key /credentials/tls.crt /credentials/tls.key /credentials/catalog-keys/catalog.pub.pem
mkdir -p /storage-credentials
cp /source/secrets/s3.json /storage-credentials/s3.json
chown -R 1000:1000 /storage-credentials
chmod 0700 /storage-credentials
chmod 0400 /storage-credentials/s3.json
