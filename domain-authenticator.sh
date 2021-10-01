#!/bin/bash

az login --identity -u "<user>"
RESOURCE_GROUP="<resourceGroup>"

DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')
NAME=""

if [ -z $DOMAIN ]
then
  DOMAIN=$CERTBOT_DOMAIN
else
  NAME=${CERTBOT_DOMAIN%".$DOMAIN"}
fi

if [ -z $NAME ]
then
  NAME="_acme-challenge"
else
  NAME="_acme-challenge.$NAME"
fi

echo "CERTBOT_DOMAIN: $CERTBOT_DOMAIN"
echo "DOMAIN: $DOMAIN"
echo "RECORD NAME: $NAME"
echo "CERTBOT_VALIDATION: $CERTBOT_VALIDATION"

az network dns record-set txt create -g $RESOURCE_GROUP -z $DOMAIN -n $NAME --ttl 120
az network dns record-set txt add-record -g $RESOURCE_GROUP -z $DOMAIN -n $NAME -v $CERTBOT_VALIDATION

sleep 25
