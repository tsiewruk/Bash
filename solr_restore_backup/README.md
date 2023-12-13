## How restore solr dump

### Run the script with sudo, specify as parameters:
* solr_host - host IP address.
* solr_port - host port.
* collection= - collection name.  
* backup_dir - path to backup.

`sudo ./restore_solr_dump.sh <solr_host> <solr_port> <collection> <backup_dir>`