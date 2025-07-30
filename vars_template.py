# AWS Access Information
AWS_ACCESS_KEY_ID = ""
AWS_SECRET_ACCESS_KEY = ""
AWS_SESSION_TOKEN = ""

# NC2 API Access Information
NC2_API_KEY = ''
NC2_KEY_ID = ''
NC2_ISSUER = '' # A unique issuer uuid, generate one from https://www.uuidgenerator.net/version4 or using the python uuid library

NC2_ORGANIZATION_ID = ''
NC2_CLOUD_ACCOUNT_ID = ''

NC2_BASE_URL = 'https://cloud.nutanix.com/api/v2'
NC2_LIST_CLUSTERS_URL = '/clusters'
NC2_CREATE_AWS_CLUSTER_URL = '/clusters/aws'
NC2_HIBERNATE_CLUSTER_URL = '/clusters/{cluster_id}/hibernate'
NC2_RESUME_CLUSTER_URL = '/clusters/{cluster_id}/resume'
NC2_TERMINATE_CLUSTER_URL = '/clusters/{cluster_id}/terminate'

NC2_GET_TASK_URL = '/tasks/{task_id}'
NC2_MAX_TIMEOUT = 7200                                              # Maximum timeout of 2 hours (in seconds)
NC2_POLLING_INTERVAL = 60                                           # Initial polling interval (in seconds)
NC2_MYNUTANIX_API_KEYS_URL = 'https://apikeys.nutanix.com'          # MyNutanix API Keys URL