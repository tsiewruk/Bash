## How restore solr dump

### Run the script with sudo, specify as parameters:
* solr_host - host IP address.
* solr_port - host port.
* collection= - collection name.  
* backup_dir - path to backup.

`sudo ./restore_solr_dump.sh <solr_host> <solr_port> <collection> <backup_dir>`

## Process Flow
The script performs the following operations:
1. Validates that it's running with root privileges
2. Checks that all required parameters are provided
3. Verifies the specified collection exists in Solr
4. Confirms the backup directory exists
5. Deletes the existing collection
6. Restores the collection from backup
7. Verifies the restoration was successful

## Docker Support
The script automatically detects if it's running inside a Docker container and adjusts the restoration parameters accordingly, adding replication and shard configuration when in Docker environments.

## Exit Codes
- `1` - Script not run as root
- `2` - Solr host parameter is empty
- `3` - Solr port parameter is empty
- `4` - Collection parameter is empty
- `5` - Backup directory parameter is empty
- `6` - Specified collection not found in Solr
- `7` - Backup directory not found

## Example
```bash
sudo ./restore_solr_dump.sh localhost 8983 my_collection /path/to/backups
```

This command will restore the `my_collection` Solr collection from backup files located in `/path/to/backups/my_collection`.

## Notes
- The script uses color-coded output for better readability
- The script expects the backup to be in a subdirectory with the same name as the collection
- Ensure your Solr instance is running and accessible before executing the script