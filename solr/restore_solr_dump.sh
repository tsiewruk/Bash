#!/bin/bash

#################################################
# script init

set -e

if [[ "$EUID" -ne 0 ]]; then
   echo -e ">> \e[31mThis script must be run as root\e[0m"
   exit 1
fi

solr_host="${1}"
solr_port="${2}"
collection="${3}"
backup_dir="${4}"

if [ -z "${solr_host}" ]; then echo -e "\e[31mSolr host is empty\e[0m"; exit 2; fi
if [ -z "${solr_port}" ]; then echo -e "\e[31mSolr port is empty\e[0m"; exit 3; fi
if [ -z "${collection}" ]; then echo -e "\e[31mCollection is empty\e[0m"; exit 4; fi
if [ -z "${backup_dir}" ]; then echo -e "\e[31mBackup dir is empty\e[0m"; exit 5; fi

function check_collection(){
    collection_list=`curl -X GET "http://${solr_host}:${solr_port}/api/collections" | jq -r '.collections[]' | grep "${collection}"`
}

# check collection list
check_collection
echo "Checking SOLR collection - '${collection}'"
if [ "${collection}" = "${collection_list}" ]; then
    echo -e ">> \e[32m ${collection} - Collection found\e[0m \n\n"
else
    echo -e ">> \e[31m ${collection} - Collection not found\e[0m"
    exit 6
fi

# check backup dir
echo -e "Checking backup dir - '${backup_dir}/${collection}'"
if [ -d "${backup_dir}/${collection}" ]; then
    echo -e ">> \e[32m ${backup_dir}/${collection} - Backup dir found\e[0m \n\n"
else
    echo -e ">> \e[31m ${backup_dir} - Backup dir not found\e[0m"
    exit 7
fi

# delete collection
echo "Removing SOLR collection - '${collection}'"
curl -X GET "http://${solr_host}:${solr_port}/solr/admin/collections?action=DELETE&name=${collection}"
echo `curl -X GET "http://${solr_host}:${solr_port}/api/collections" | jq -r '.collections[]'`
if [ -z `curl -X GET "http://${solr_host}:${solr_port}/api/collections" | jq -r '.collections[]' | grep "${collection}"` ]; then echo -e ">> \e[32m${collection} removed\e[0m\n\n"; else echo -e ">> \e[31m${collection} not removed\e[0m"; fi

# restore collection
system_status=`cat /proc/1/cgroup | head -n1 | awk -F 'docker' '{print FS}'`
echo -e "Restoring SOLR collection - '${collection}'"
if [ ! "${system_status}" = "docker" ]; then
    curl -X GET "http://${solr_host}:${solr_port}/solr/admin/collections?action=RESTORE&name=${collection}&collection=${collection}&location=${backup_dir}"
else
    curl -X GET "http://${solr_host}:${solr_port}/solr/admin/collections?action=RESTORE&name=${collection}&collection=${collection}&maxShardsPerNode=1&replicationFactor=1&location=${backup_dir}"
fi
check_collection
if [ "${collection}" = "${collection_list}" ]; then echo -e ">> \e[32m${collection} restored\e[0m"; else echo -e ">> \e[31m${collection} not restored\e[0m"; fi