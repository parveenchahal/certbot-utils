cert_name_list=$1
frequency_in_second=$2
pfx_path="."
if [ ! -z $3 ]
then
  pfx_path=$3
fi

if [ -z $cert_name_list ]
then
  echo "Provide space separated cert name list"
  exit
fi

if [ -z $frequency_in_second ]
then
  echo "Provide frequency in seconds"
  exit
fi

renew()
{
  date
  echo "Renewing cert"
  certbot renew
  for c in $cert_name_list; do
    cert_path="/etc/letsencrypt/live/$c/fullchain.pem"
    key_path="/etc/letsencrypt/live/$c/privkey.pem"
    openssl pkcs12 -export -out "$pfx_path/$c" -inkey $key_path -in $cert_path -passout pass:
    echo "Exported $c"
  done
}

while true
do
  renew
  echo "Sleeping for $frequency_in_second seconds"
  sleep $frequency_in_second
done