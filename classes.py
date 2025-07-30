import jwt
import os
import datetime
# import time
import hmac
import hashlib
import base64
# import pytz
import uuid
import requests
import json
import ipaddress
from copy import deepcopy
from pathlib import Path
from tofupy import Tofu
from jinja2 import Template
from vars import *

class nc2Cluster:
    def __init__(self):
        self.number = None
        self.name = None
        self.substrate = None
        self.build_payload = {}
        self.build_response = None

        self.pc_subnet_cidr = None
        self.pc_subnet_id = None
        self.pc_vip = None
        self.pc_ips = None
        self.flow_subnet_cidr = None
        self.flow_subnet_id = None
        self.access_url = None
    
    def json(self): 
        return {"number": self.number,
                  "name": self.name,
                  "substrate": self.substrate,
                  "payload": self.build_payload,
                  "build_response": self.build_response,
                  "pc_subnet_cidr": self.pc_subnet_cidr,
                  "pc_subnet_id": self.pc_subnet_id,
                  "pc_vip": self.pc_vip,
                  "pc_ips": self.pc_ips,
                  "flow_subnet_cidr": self.flow_subnet_cidr,
                  "flow_subnet_id": self.flow_subnet_id,
                  "access_url": self.access_url
                  }

class LabBuild:
    def __init__(self, args):
        self.debug_logs = True

        self.args = args
        self.substrate = "aws"
        self.build_params = {}
        self.networks = {}
        self.aws_params = {
            "project_prefix": "",
            "vpc_region": "",
            "vpc_az": "",
            "vpc_cidr": "",
            "cluster_count": 0,
        }
        self.aws_objects = {}

        # make root folder
        if self.args.directory:
            self.directory = self.args.directory
        else:
            self.directory = "nc2-lab-" + str(datetime.today().date())
            print(f"No directory name provided, using default {self.directory}")
        try:
            os.mkdir(self.directory)
            self.pwd = Path(self.directory)
            print(f"'{self.directory}' directory created successfully.")
            self.state = "new"
        except FileExistsError:
            self.pwd = Path(self.directory)
            print(f"Directory '{self.directory}' already exists.")
            self.state = "existing"
        except PermissionError:
            print(f"Permission denied: Unable to create '{self.directory}'.")
        except Exception as e:
            print(f"An error occurred: {e}")
            quit()

        # make clusters folder
        self.cluster_dir = os.path.join(self.directory, "clusters")
        try:            
            os.mkdir(self.cluster_dir)
            print(f"'{self.cluster_dir}' directory created successfully.")
            self.state = "new"
        except FileExistsError:
            print(f"Directory '{self.cluster_dir}' already exists.")
        except PermissionError:
            print(f"Permission denied: Unable to create '{self.cluster_dir}'.")
        except Exception as e:
            print(f"An error occurred: {e}")
            quit()
        
        #make cloud folder
        self.cloud_dir = os.path.join(self.directory, "cloud")
        try:            
            os.mkdir(self.cloud_dir)
            print(f"'{self.cloud_dir}' directory created successfully.")
            self.state = "new"
        except FileExistsError:
            print(f"Directory '{self.cloud_dir}' already exists.")
        except PermissionError:
            print(f"Permission denied: Unable to create '{self.cloud_dir}'.")
        except Exception as e:
            print(f"An error occurred: {e}")
            quit()
        
        # maybe?
        
        self.logfile = open(os.path.join(self.directory, "logfile.txt"), "a")

        try:
            self.tfstate_file = open(os.path.join(self.directory, "terraform.tfstate"),"r")
            self.tfstate = json.loads(self.tfstate_file.read())
            self.tfstate_file.close()
        except:
            self.tfstate = None

    def log(self, message, logonly=False, level="INFO"):
        now = str(datetime.datetime.now().isoformat())
        log_message = f"{now} - {level} - {message}"
        if logonly == False:
            print(log_message)
        self.logfile.write(f"{log_message}\n")
        if level == "FAIL":
            quit()

    def fail(self, message):
        now = str(datetime.datetime.now().isoformat())
        log_message = f"{now} - FAIL - {message}"
        print(log_message)
        self.logfile.write(f"{log_message}\n")
        quit()

    def read_params_from_file(self): 
        try:
            params_in_file = open(self.args.json, "r")
            self.build_params = json.loads(params_in_file.read())
            params_in_file.close()
            params_out_file = open(os.path.join(self.directory,"build_params.json"),"w")
            params_out_file.write(json.dumps(self.build_params,indent=2))
            params_out_file.close()
            self.log(f"Reading from provided parameters file {self.args.json}")
        except Exception as e:
            self.fail(f"Cannot read provided parameters file: {e}")

        for param, info in self.build_params.items():
            if info["type"] == "int" and isinstance(info["val"], int) == False:
                self.fail(
                    f"ERROR: {info['name']} must be an integer. Correct the input file and try again."
                )
            elif info["type"] == "list" and isinstance(info["val"], list) == False:
                self.fail(
                    f"ERROR: {info['name']} must be a list. Correct the input file and try again."
                )
            elif info["type"] == "str" and isinstance(info["val"], str) == False:
                self.fail(
                    f"ERROR: {info['name']} must be a string. Correct the input file and try again."
                )
            else:
                self.log(f"Parameter: {param} | Value: {info["val"]}")
        return

    def manual_params_input(self): # this is messy and can be better. 
        try:
            params_file = open("build_params.json", "r")
            self.build_params = json.loads(params_file.read())
            self.log(f"No parameters file provided, gathering user-provided input.")
        except Exception as e:
            self.fail(f"Default build parameters file build_params.json not found.")

        print(
            "Provide required information. Enter ? for help. Default values, when available, will be shown. To accept default value, press enter."
        )
        for param,info in self.build_params.items():  # Iterate through the build options to gather info
            this_val = ""  # set current response to empty
            while this_val == "":  # Loop until we have a response
                print(info["desc"])  # Print the build option description
                if info["default"] != None:  # if there is a default value
                    print(
                        f"Default: {info['default']}"
                    )  # show the current default value
                this_val = input("> ")  # look for a response

                if this_val == "?":  # if ?
                    this_val = ""  # blank the response
                    print(info["help"])  # print the option's help test
                elif (
                    this_val == "" and info["default"] != ""
                ):  # if the option is blank and there is a default
                    this_val = info["default"]  # set the response to the default
                elif (
                    this_val == "" and info["default"] == None
                ):  # if no default and no answer given
                    print(
                        "This option has no default value, and must be user-supplied."
                    )  # Print message and then loop
                    continue

            if info["type"] == "int":
                try:
                    self.build_params[param]["val"] = int(this_val)
                except:
                    print("Error: Provide an integer.")
                    response = ""
            elif info["type"] == "list":
                try:
                    this_val = this_val.split(",")
                    for r in range(0, len(this_val)):
                        this_val[r] = this_val[r].strip()
                    self.build_params[param]["val"] = this_val
                except:
                    print("Error: Please provide a comma-seperated list.")
                    this_val = ""
            else:
                self.log(f"Parameter: {param} | Value: {this_val}")
                self.build_params[param]["val"] = this_val  # store the response

        try:
            params_out_file = open(os.path.join(self.directory,"build_params.json"))
            params_out_file.write(json.dumps(self.build_params,indent=2))
            params_out_file.close()
        except Exception as e:
            self.fail(f"Unable to write parameters file to project directory: {e}")

    def validate_info(self): # this is messy and can be betters.
        if self.build_params["cluster_count"]["val"] == 0:
            self.log(
                """Cluster count of 0 provided. VPC networking will be built 
                  but no clusters will be created. No Flow subnets will be created.
                  Is this OK? Input Y to proceed, N to quit.
                """
            )
            while True:
                proceed = input("[Yy]es/[Nn]o? ")
                if proceed.upper() == "N":
                    self.fail("User aborted.")
                elif proceed.upper() == "Y":
                    self.log(
                        "User accepted. Proceeding with public cloud network build only."
                    )
                    break

        elif self.build_params["cluster_count"]["val"] < 0:
            self.fail("Cannot build a negative number of clusters.")
        elif self.build_params["cluster_count"]["val"] > 10:
            self.fail("This tool only supports a maximum of 10 clusters per build.")

        self.log("Validating networking...")
        try:
            cidr_network = ipaddress.IPv4Network(self.build_params["vpc_cidr"]["val"])
            cidr_prefixlen = cidr_network.prefixlen
            if cidr_prefixlen > 20:

                self.fail("ERROR: VPC CIDR prefix length must be at least /20.")
            self.networks["vpc"] = str(cidr_network)
            self.log(f"VPC CIDR: {self.networks['vpc']}")
        except Exception as e:
            self.fail(f"VPC CIDR invalid. Error: {e}")

        try:
            cidr_subnets = list(cidr_network.subnets(new_prefix=24))
            self.networks["vpc_public"] = str(cidr_subnets[0])
            self.log(f"VPC Public Subnet: {self.networks['vpc_public']}")

            self.networks["cluster_management"] = str(cidr_subnets[1])
            self.log(
                f"VPC Metal/Cluster Mgmt Subnet: {self.networks['cluster_management']}"
            )

            for i in range(0, self.build_params["cluster_count"]["val"]):
                self.networks["prism_central_" + str(i)] = str(cidr_subnets[10 + i])
                self.log(
                    f"Cluster {i} Prism Central Subnet: {self.networks['prism_central_'+str(i)]}"
                )

            for i in range(0, self.build_params["cluster_count"]["val"]):
                self.networks["flow_network_" + str(i)] = str(cidr_subnets[20 + i])
                self.log(
                    f"Cluster {i} Flow Subnet: {self.networks['flow_network_'+str(i)]}"
                )
        except Exception as e:
            self.fail(
                "The provided VPC CIDR subnet is insufficient to proceed with the requested number of clusters."
            )

        self.log("Validating Management Access IPs")
        for ip in self.build_params["access_ips"]["val"]:
            try:
                ipaddress.IPv4Network(ip)
                self.log(f"{ip} is a valid IPv4 Network Address.")
            except Exception as e:
                self.fail(f"ERROR: {ip} is not a valid IPv4 network address.")

        return

    def set_aws_params(self):
        self.log("Setting AWS Parameters for template files.")
        if AWS_ACCESS_KEY_ID:
            self.aws_params["access_key"] = AWS_ACCESS_KEY_ID
            self.log(f"AWS Access Key: {self.aws_params["access_key"]}")
        else:
            self.fail("No AWS Access Key Provided.")
        if AWS_SECRET_ACCESS_KEY:
            self.aws_params["access_secret"] = AWS_SECRET_ACCESS_KEY
            self.log(f"AWS Secret Key: NOT LOGGED")
        else:
            self.fail("No AWS Secret Key Provided.")
        if AWS_SESSION_TOKEN:
            self.aws_params["token"] = AWS_SESSION_TOKEN
            self.log(f"AWS Session Token: NOT LOGGED")

        self.aws_params["project_prefix"] = self.build_params["prefix"]["val"]
        self.log(f"Project Prefix: {self.aws_params["project_prefix"]}")

        self.aws_params["vpc_region"] = self.build_params["region"]["val"]
        self.log(f"AWS Region: {self.build_params["region"]["val"]}")

        self.aws_params["vpc_az"] = self.build_params["az"]["val"]
        self.log(f"AWS Availability Zone: {self.build_params["az"]["val"]}")

        self.aws_params["cluster_count"] = self.build_params["cluster_count"]["val"]
        self.log(f"Cluster Count: {str(self.build_params["cluster_count"]["val"])}")

        self.aws_params["vpc_cidr"] = self.networks["vpc"]
        self.log(f"AWS VPC CIDR: {self.networks["vpc"]}")

        self.aws_params["access_ips"] = self.build_params["access_ips"]["val"]
        self.log(
            f"Management Access IPs: {str(self.build_params["access_ips"]["val"])}"
        )

        try:
            aws_params_out_file = open(os.path.join(self.directory,"aws_params.json"),"w")
            aws_params_out_file.write(json.dumps(self.aws_params,indent=2))
            aws_params_out_file.close()
        except Exception as e:
            self.fail(f"Unable to write AWS parameters file to project directory: {e}")

        return

    def render_template(self, folder, template, values):
        """
        Reads and renders a jinja template
        """
        try:
            self.log(f"Opening {template}.tf.j2 for reading.")
            template_file = open(os.path.join("templates", f"{template}.tf.j2"), "r")
        except Exception as e:
            self.fail(f"Unable to read {template}.tf.j2: {e}")

        try:
            self.log(f"Opening {template}.tf for writing.")
            template_output = open(os.path.join(self.directory, folder, f"{template}.tf"), "w")
        except Exception as e:
            self.fail(f"Unable to create {template}.tf: {e}")

        try:
            self.log("Parsing template file.")
            template = Template(template_file.read())
            template_file.close()
        except Exception as e:
            self.fail(f"Unable to parse {template}.tf.j2: {e}")

        try:
            self.log("Rendering output.")
            template_output.write(template.render(values))
            template_output.close()
        except Exception as e:
            self.fail(f"Error rendering output file: {e}")

        return

    def build_aws_networking(self):
        """
        Builds AWS networking via OpenTofu using generated configuration in provided directory.
        """
        tofu = Tofu(cwd=self.pwd)
        try:
            self.log("Initializing OpenTofu Project for AWS Networking.")
            self.init = tofu.init()
        except Exception as e:
            self.fail(f"Failed to initialize OpenTofu project: {e}")

        self.log("Planning OpenTofu Project for AWS Networking")
        self.plan_log, self.plan = tofu.plan()
        if not self.plan or self.plan.errored:
            self.fail(f"OpenTofu Plan Failed: {self.plan_log}")
            return False, self.plan_log

        try:
            self.log("Applying OpenTofu Project for AWS Networking")
            self.apply_log = tofu.apply()
            self.log("OpenTofu Log:")
            self.log(self.apply_log)
            return True, self.apply_log
        except Exception as e:
            self.fail(
                f"OpenTofu plan failed to apply: {e}\nOpenTofu Apply Log:\n{self.apply_log}"
            )
            return False, self.apply_log

    def refresh_aws_networking(self):
        tofu = Tofu(cwd=self.pwd)

        self.log("Running Tofu Plan to refresh state")
        self.plan_log, self.plan = tofu.plan()
        if not self.plan or self.plan.errored:
            self.fail(f"OpenTofu Plan Failed: {self.plan_log}")
            return False, self.plan_log
        
        try:
            self.tfstate = tofu.state().data
        except Exception as e:
            self.fail(f"Failed to retrieve state for OpenTofu project: {e}")

    def get_aws_created_objects(self):
        """
        Reads the tfstate to get the created objects and their IDs.
        """
        self.log("Getting details of AWS Created Objects from tfstate file.")
        try:
            tfstate_file = open(os.path.join(self.directory, "terraform.tfstate"), "r")
            tfstate_json = json.load(tfstate_file)
        except Exception as e:
            self.fail(f"Unable to read {tfstate_file}: {e}")

        for resource in tfstate_json["resources"]:
            resource_name = resource["name"]
            resource_id = resource["instances"][0]["attributes"]["id"]
            self.log(f"{resource_name}: {resource_id}")
            self.aws_objects[resource_name] = resource_id
        
        try:
            aws_objects_out_file = open(os.path.join(self.directory,"aws_objects.json"),"w")
            aws_objects_out_file.write(json.dumps(self.aws_objects,indent=2))
            aws_objects_out_file.close()
        except Exception as e:
            self.fail(f"Unable to write AWS created objects file to project directory: {e}")
        return

    def build_nc2_cluster_objects(self):
        self.log("Building NC2 Cluster Objects")
        self.nc2_cluster_base_payload = {
            "data": {
                "organization_id": NC2_ORGANIZATION_ID,
                "cloud_account_id": NC2_CLOUD_ACCOUNT_ID,
                "region": self.build_params["region"]["val"],
                "name": "",
                "aos_version": self.build_params["aos_version"]["val"],
                "license": "nci",
                "software_tier": self.build_params["software_tier"]["val"],
                "use_case": "general",
                "capacity": [
                    {
                        "host_type": self.build_params["host_type"]["val"],
                        "number_of_hosts": self.build_params["host_qty"]["val"],
                    }
                ],
                 "cluster_fault_tolerance": {
                    "factor": "1N/1D"
                 },
                "host_access_ssh_key": self.build_params["ssh_key"]["val"],
                "network": {
                    "management_subnet": self.aws_objects["private_metal_subnet"],
                    "availability_zone": self.build_params["az"]["val"],
                    "fvn_config": {
                        "subnet_cidr": "",
                        "subnet_cloud_id": "",
                    },
                    "fvn_enabled": True,
                    "management_services_access_policy": {
                        "mode": "restricted",
                        "ip_addresses": self.build_params["access_ips"]["val"],
                    },
                    "mode": "existing",
                    "prism_element_access_policy": {
                        "mode": "restricted",
                        "ip_addresses": self.build_params["access_ips"]["val"],
                    },
                    "test_network_connectivity": True,
                    "vpc": self.aws_objects["vpc"],
                    "vpc_cidr": self.networks["vpc"],
                },
                "prism_central": {
                    "management_subnet": "",
                    "mode": "new",
                    "ntp_server_ip_list": [
                        "0.pool.ntp.org",
                        "1.pool.ntp.org",
                        "2.pool.ntp.org",
                    ],
                    "version": self.build_params["pc_version"]["val"],
                    "vm_size": self.build_params["pc_size"]["val"],
                },
            }
        }
        self.log(
            f"NC2 Cluster Base Payload: \n{json.dumps(self.nc2_cluster_base_payload,indent=2)}",
            logonly=True,
        )
        self.nc2_clusters = {}
        for c in range(0, self.build_params["cluster_count"]["val"]):
            this_cluster = nc2Cluster()
            this_cluster.name = self.build_params["prefix"]["val"] + "-" + str(c)
            this_cluster.number = c
            self.log(f"Building NC2 Cluster {str(c)}: {this_cluster.name}")

            this_cluster.pc_subnet_cidr = self.networks["prism_central_" + str(c)]
            self.log(f"Prism Central Subnet: {this_cluster.pc_subnet_cidr}")

            this_cluster.pc_subnet_id = self.aws_objects["private_pc_subnet_" + str(c)]
            self.log(f"Prism Central Subnet ID: {this_cluster.pc_subnet_id}")

            this_cluster.flow_subnet_cidr = self.networks["flow_network_" + str(c)]
            self.log(f"Flow Networking Subnet: {this_cluster.flow_subnet_cidr}")

            this_cluster.flow_subnet_id = self.aws_objects[
                "private_flow_subnet_" + str(c)
            ]
            self.log(f"Flow Networking Subnet ID: {this_cluster.flow_subnet_id}")

            self.log("Building cluster payload dictionary...")
            this_cluster.build_payload = deepcopy(self.nc2_cluster_base_payload)
            this_cluster.build_payload["data"]["name"] = (
                self.build_params["prefix"]["val"] + "-" + str(c)
            )
            this_cluster.build_payload["data"]["prism_central"]["management_subnet"] = (
                self.aws_objects["private_pc_subnet_" + str(c)]
            )
            this_cluster.build_payload["data"]["network"]["fvn_config"]["subnet_cidr"] = (
                self.networks["flow_network_" + str(c)]
            )
            this_cluster.build_payload["data"]["network"]["fvn_config"]["subnet_cloud_id"] = (
                self.aws_objects["private_flow_subnet_" + str(c)]
            )
            self.log(
                f"Payload: \n{json.dumps(this_cluster.build_payload,indent=2)}\n#############\n",
                logonly=True,
            )
            self.nc2_clusters[c] = this_cluster

    def create_nc2_jwt(self):
        """
        Create a JWT token using the provided API key and key ID.

        Returns:
            The JWT token and it's expiry if successful, None otherwise.
        """

        try:
            self.log("Getting JWT token for NC2 API.")
            curr_time = datetime.datetime.now(datetime.UTC)
            payload = {
                "aud": NC2_MYNUTANIX_API_KEYS_URL,
                "iat": curr_time,
                "exp": curr_time
                + datetime.timedelta(
                    seconds=600
                ),  # Nutanix recommends a 5 minute expiry
                "iss": NC2_ISSUER,
                "metadata": {"reason": "NC2 AWS Cluster Quick Starter"},
                "context": {},
            }
            body = "{}".format(NC2_KEY_ID)
            signature = base64.b64encode(
                hmac.new(
                    bytes(NC2_API_KEY, "latin-1"),
                    bytes(body, "latin-1"),
                    digestmod=hashlib.sha512,
                ).digest()
            )
            token = jwt.encode(
                payload, signature, algorithm="HS512", headers={"kid": NC2_KEY_ID}
            )

            self.jwt_token, self.jwt_token_exp = token, payload["exp"]
            self.log(
                f"JWT Token: {self.jwt_token} | Token Expiration: {self.jwt_token_exp}"
            )
            return

        except Exception as e:
            self.fail(f"JWT generation failed: {str(e)}")

    def request_nc2_aws_clusters(self):
        self.log("Requesting NC2 Clusters via API.")
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            for c, cluster in self.nc2_clusters.items():
                try:
                    cluster_state_file = open(os.path.join(self.cluster_dir, f"{c}.json"), "r")
                    cluster_state = json.loads(cluster_state_file.read())
                    cluster_state_file.close()
                except:
                    cluster_state = None

                if cluster_state == None:
                    self.logfile = open(os.path.join(self.directory, "logfile.txt"), "w")
                    self.log(f"Requesting cluster {cluster.number}: {cluster.name}")
                    # Send a POST request to create the cluster
                    response = requests.post(
                        NC2_BASE_URL + NC2_CREATE_AWS_CLUSTER_URL,
                        json=cluster.build_payload,
                        headers=headers,
                    )
                    self.log(f"URL: {response.url}")
                    self.log(f"Headers: \n{json.dumps(headers,indent=2)}")
                    self.log(f"Payload: \n{json.dumps(cluster.build_payload, indent=2)}")

                    if response.status_code == 202:
                        cluster.build_response = response.json()
                        self.log(
                            f"Request successful. Response: \n{json.dumps(cluster.build_response,indent=2)}"
                        )
                        cluster_state_file = open(os.path.join(self.cluster_dir, f"{c}.json"), "w")
                        cluster_json = cluster.json()            
                        cluster_state_file.write(json.dumps(cluster_json,indent=2))
                        cluster_state_file.close()
                    else:
                        self.fail(
                            f"Cluster creation failed with status code {response.status_code}, error {response.text}"
                        )
                else:
                    self.log(f"Cluster {c} already requested, passing.")
        except Exception as e:
            self.fail(f"Error creating cluster: {str(e)}")

    def get_nc2_built_clusters(self):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            params = {"active": "true", "name": self.build_params["prefix"]["val"]}
            response = requests.get(
                NC2_BASE_URL + NC2_LIST_CLUSTERS_URL, params=params, headers=headers
            )

            if response.status_code == 200:
                self.built_clusters = response.json()["data"]
            else:
                raise Exception(
                    f"Cluster list failed with status code {response.status_code}, error {response.text}"
                )

        except Exception as e:
            raise Exception(f"Error listing clusters: {str(e)}")
        
    def get_nc2_cluster_id_by_name(self,name = "nc2-flow-lab-0"):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            params = {"active": "true", "name": name}

            response = requests.get(
                NC2_BASE_URL + NC2_LIST_CLUSTERS_URL, params=params, headers=headers
            )

            if response.status_code == 200:
                response_data = response.json()
                if len(response_data['data']) > 1:
                    pass
                cluster_id = response_data['data'][0]['id']
                print(cluster_id)
                return cluster_id
            else:
                raise Exception(
                    f"Cluster list failed with status code {response.status_code}, error {response.text}"
                )

        except Exception as e:
            raise Exception(f"Error listing clusters: {str(e)}")

    def get_nc2_cluster_by_id(self,id):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            response = requests.get(
                NC2_BASE_URL + NC2_LIST_CLUSTERS_URL + '/' + id, headers=headers
            )

            if response.status_code == 200:
                response_data = response.json()
                print(response_data)
            else:
                raise Exception(
                    f"Cluster list failed with status code {response.status_code}, error {response.text}"
                )

        except Exception as e:
            raise Exception(f"Error listing clusters: {str(e)}")    
    
    def get_nc2_prism_centrals(self):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            # logging.debug(headers)
            params = {"availability_zone": self.build_params["az"]["val"]}
            response = requests.get(
                NC2_BASE_URL
                + "/cloud-accounts/"
                + NC2_CLOUD_ACCOUNT_ID
                + "/regions/"
                + self.build_params["region"]["val"]
                + "/prism-centrals",
                params=params,
                headers=headers,
            )

            if response.status_code == 200:
                self.prism_centrals = response.json()["data"]
                for pc in self.prism_centrals:
                    if pc["vpc"] == self.aws_objects["vpc"]:
                        for cluster, data in self.nc2_clusters.items():
                            if data.pc_subnet_id == pc["management_subnet"]:
                                data.pc_vip = pc["pc_virtual_ip"]
                                data.pc_ips = pc["vm_ips"]
                                print(f"{cluster} - {pc['pc_virtual_ip']}")
                                pass
            else:
                raise Exception(
                    f"Prism Central list failed with status code {response.status_code}, error {response.text}"
                )

        except Exception as e:
            raise Exception(f"Error listing Prism Centrals: {str(e)}")

    def generate_aws_nlb_config(self):

        nlb_template_output = open(os.path.join(self.directory, "aws_nlb.tf"), "w")
        nlb_template_file = open(os.path.join("templates", "aws_nlb.tf.j2"), "r")
        nlb_template = Template(nlb_template_file.read())
        nlb_template_file.close()

        for cluster, info in self.nc2_clusters.items():
            nlb_config = {
                "project_prefix": self.aws_params["project_prefix"],
                "cluster_name": info.name,
                "cluster_number": info.number,
                "pc_vip": info.pc_vip,
                "pc_cidr": info.pc_subnet_cidr,
            }
            nlb_template_output.write(nlb_template.render(nlb_config))

        nlb_template_output.close()
        return

    def close_files(self):
        self.logfile.close()
        self.statefile.close()

