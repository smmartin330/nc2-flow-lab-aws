# Constants and Configurations

API_KEY = 'YOUR_API_KEY'                                       
KEY_ID = 'YOUR_KEY_ID'
ISSUER = 'RANDOM_UUID'    # A unique issuer uuid, generate one from https://www.uuidgenerator.net/version4 or using the python uuid library

NC2_BASE_URL = 'https://cloud.nutanix.com/api/v2'
CREATE_CLUSTER_URL = '/clusters/aws'
HIBERNATE_CLUSTER_URL = '/clusters/{cluster_id}/hibernate'
RESUME_CLUSTER_URL = '/clusters/{cluster_id}/resume'
TERMINATE_CLUSTER_URL = '/clusters/{cluster_id}/terminate'

GET_TASK_URL = '/tasks/{task_id}'
MAX_TIMEOUT = 7200                                              # Maximum timeout of 2 hours (in seconds)
POLLING_INTERVAL = 60                                           # Initial polling interval (in seconds)
MYNUTANIX_API_KEYS_URL = 'https://apikeys.nutanix.com'          # MyNutanix API Keys URL