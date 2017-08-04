# Controller-HA-for-GCP
Aviatrix Controller HA monitor and restart for Google Cloud


This script is meant to monitor the controller instance in GCP. Before you run the script make sure the following information is in place.

1.	An Ubuntu instance with python and gcloud SDK library  along with gce_backend_service.py script
2.	Name of controller instance
3.	Zone where the controller instance is running
4.	Google Could project credential  (copy the file into path)

The script uses GCE backend monitoring and restart the controller instance if a failure is detected. 
 
usage:

python gce_backend_service.py instance-name instance-zone project-credentials

Eg:

python gce_backend_service.py dry-test us-east1-b /var/cloudx/ucc-gcloud.json
