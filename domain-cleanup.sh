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

echo $DOMAIN
echo $NAME
az network dns record-set txt delete -y -g $RESOURCE_GROUP -z $DOMAIN -n $NAME