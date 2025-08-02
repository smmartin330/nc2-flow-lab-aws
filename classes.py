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
        self.project = None
        self.cluster_id = None
        self.substrate = None
        self.state_file = None

        self.cluster_data = None
        self.hosts = None

        self.create_payload = {}
        self.create_status_code = None
        self.create_response = None
        self.created = False

        self.pc_subnet_cidr = None
        self.pc_subnet_id = None
        self.pc_vip = None
        self.pc_ips = None
        self.flow_subnet_cidr = None
        self.flow_subnet_id = None
        self.access_url = None
        self.pc_user = "admin"
        self.pc_password = "Nutanix.123"

    def create_aws(self, jwt):
        """
        Sends the create AWS cluster API call.

        Attributes:
            jwt (str): The JWT token for API authentication

        Returns:
            created (bool): True if the build request is successful, false if it is not.
            create_status_code (int): The HTTP status code from the API call
            create_response (dict): The API response
        """
        self.substrate = "aws"

        headers = {
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.created == True:
            print(f"{self.name} already successfully created, skipping.")
            return self.created, self.create_status_code, self.create_response
        else:
            response = requests.post(
                NC2_BASE_URL + NC2_CREATE_AWS_CLUSTER_URL,
                json=self.create_payload,
                headers=headers,
            )

            self.create_status_code = response.status_code
            self.create_response = response.json()

            if response.status_code == 202:
                self.created = True

            return self.created, self.create_status_code, self.create_response

    def get_cluster_id(self, jwt):
        headers = {
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        params = {"active": "true", "name": self.name}

        response = requests.get(
            NC2_BASE_URL + NC2_LIST_CLUSTERS_URL, params=params, headers=headers
        )

        if response.status_code == 200:
            response_data = response.json()
            if len(response_data["data"]) > 1:
                # This would be unexpected, as with a 10 cluster limit and numbering starting at 0, there should never be two matches.
                # The first would be project-0, the last would be project-9.
                # Still, this situation should be handled eventually.
                pass
            self.cluster_id = response_data["data"][0]["id"]
            return self.cluster_id
        else:
            return False

    def get_cluster(self, jwt):
        headers = {
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        response = requests.get(
            NC2_BASE_URL + NC2_LIST_CLUSTERS_URL + "/" + self.cluster_id,
            headers=headers,
        )

        if response.status_code == 200:
            response_data = response.json()
            self.cluster_data = response_data["data"]
            self.hosts = response_data["data"]["hosts"]
            self.pc_ips = response_data["data"]["prism_central"]["vm_ips"]
            self.pc_vip = response_data["data"]["prism_central"]["pc_virtual_ip"]
            return self.cluster_data
        else:
            return False

    def write_state_file(self):
        file = open(self.state_file, "w")
        file.write(json.dumps(self.__dict__, indent=2))
        file.close()

    def load_state_file(self):
        try:  # Read cluster state file
            file = open(self.state_file)
            state = json.loads(file.read())
            file.close()
        except Exception as e:
            self.fail(f"Unable to load cluster state for cluster {self.number}: {e}")
        for (
            k,
            v,
        ) in state.items():  # Load data from cluster state file into cluster object
            self.__dict__[k] = v

class AWS:
    def __init__(self,project,directory):
        self.project = project,
        self.region = "",
        self.az = "",
        self.vpc_cidr = "",
        self.cluster_count = 0,
        self.access_ips = [],
        self.access_key = "",
        self.access_secret = "",
        self.token = "",
        self.state_file = os.path.join(directory,"cloud","aws.json")
        self.objects = {}

    def tofu(self,action):
        match action:
            case "init":
                try:
                    self.log("Initializing OpenTofu Project for Cloud Networking.")
                    self.init = self.tofu.init()
                except Exception as e:
                    self.fail(f"Failed to initialize OpenTofu project: {e}")
            case "plan":
                try:
                    self.log("Planning OpenTofu Project for Cloud Networking")
                    self.plan_log, self.plan = self.tofu.plan()
                    if not self.plan or self.plan.errored:
                        self.fail(f"OpenTofu Plan Failed: {self.plan_log}")
                except Exception as e:
                    self.fail(f"Failed to run tofu plan: {e}")
            case "apply":
                try:
                    self.log("Applying OpenTofu Project for AWS Networking")
                    self.apply_log = self.tofu.apply()
                    self.log("OpenTofu Log:")
                    self.log(self.apply_log)
                    return True, self.apply_log
                except Exception as e:
                    self.fail(
                        f"OpenTofu plan failed to apply: {e}\nOpenTofu Apply Log:\n{self.apply_log}"
                    )
            case "get_aws_ids":
                self.log("Getting details of AWS Created Objects from tfstate file.")
                try:
                    tfstate_file = open(
                        os.path.join(self.directory, "cloud", "terraform.tfstate"), "r"
                    )
                    tfstate_json = json.load(tfstate_file)
                except Exception as e:
                    self.fail(
                        f"Unable to read {tfstate_file} from project cloud directory: {e}"
                    )

                for resource in tfstate_json["resources"]:
                    resource_name = resource["name"]
                    resource_id = resource["instances"][0]["attributes"]["id"]
                    self.log(f"{resource_name}: {resource_id}")
                    self.aws_objects[resource_name] = resource_id
                    if resource["type"] == "aws_lb":
                        self.aws_objects["lb_dns_name"] = resource["instances"][0][
                            "attributes"
                        ]["dns_name"]

                try:
                    aws_objects_out_file = open(
                        os.path.join(self.directory, "aws_objects.json"), "w"
                    )
                    aws_objects_out_file.write(json.dumps(self.aws_objects, indent=2))
                    aws_objects_out_file.close()
                    return
                except Exception as e:
                    self.fail(
                        f"Unable to write AWS created objects file to project directory: {e}"
                    )

    def write_state_file(self):
        file = open(self.state_file, "w")
        file.write(json.dumps(self.__dict__, indent=2))
        file.close()

    def load_state_file(self):
        try:  # Read cloud state file
            file = open(self.state_file)
            state = json.loads(file.read())
            file.close()
        except Exception as e:
            self.fail(f"Unable to load AWS cloud state file: {e}")
        for (
            k,
            v,
        ) in state.items():  # Load data from cluster state file into cluster object
            self.__dict__[k] = v

class LabBuild:
    def __init__(self, args):
        self.args = args
        self.substrate = "aws"
        self.build_params = {}
        self.networks = {}
        self.aws_params = {
            "project_project": "",
            "vpc_region": "",
            "vpc_az": "",
            "vpc_cidr": "",
            "cluster_count": 0,
        }
        self.aws_objects = {}

        # make project folder
        if self.args.directory:
            self.directory = self.args.directory
        else:
            self.directory = "nc2-lab-" + str(datetime.today().date())
            print(f"No directory name provided, using default {self.directory}")
        try:
            os.mkdir(self.directory)
            print(f"'{self.directory}' directory created successfully.")
            self.state = "new"
        except FileExistsError:
            print(f"Directory '{self.directory}' already exists.")
            self.state = "existing"
        except PermissionError:
            print(f"Permission denied: Unable to create '{self.directory}'.")
        except Exception as e:
            print(f"An error occurred: {e}")
            quit()
        self.path = Path(self.directory)

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
        self.clusters_path = Path(os.path.join(self.directory, "clusters"))

        # make cloud folder
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
        self.cloud_path = Path(os.path.join(self.directory, "cloud"))

        self.tofu = Tofu(cwd=self.cloud_path)

        self.logfile = open(os.path.join(self.directory, "logfile.txt"), "a")

        try:
            self.tfstate_file = open(
                os.path.join(self.directory, "cloud", "terraform.tfstate"), "r"
            )
            self.tfstate = json.loads(self.tfstate_file.read())
            self.tfstate_file.close()
        except:
            self.tfstate = None

    def log(self, text, logonly=False, level="INFO"):
        """
        Logs to console and/or the logfile defined in the LabBuild object.

        Attributes:
            text (str):
                The log message text
            logonly (bool):
                If set to True, log message is only written to file and not out to console. Default is False
            level (str):
                The logging level. Default is 'INFO'. If level sent is 'FAIL', this will call the FAIL method resulting in the script terminating.
                Failures should call the *fail()* method, however.

        Returns:
            message: A string containing the log message.
        """
        if level == "FAIL":
            self.fail(text=text)
        else:
            now = str(datetime.datetime.now().isoformat())
            message = f"{now} - {level} - {text}"
            if logonly == False:
                print(message)
            self.logfile.write(f"{message}\n")

    def fail(self, text):
        """
        Logs a failure message to console and the logfile defined in the LabBuild object and terminates the script.

        Attributes:
            text (str):
                The log message text

        Returns:
            Nothing; Terminates the script.
        """
        now = str(datetime.datetime.now().isoformat())
        log_message = f"{now} - FAIL - {text}"
        print(log_message)
        self.logfile.write(f"{log_message}\n")
        quit()

    def read_params_from_file(self):
        """
        Reads and parses the build parameter file requested,
        validates each parameter is the appropriate data type,
        and writes the parameter file to the project directory.

        Attributes:
            None

        Returns:
            None
        """
        try:
            params_in_file = open(self.args.json, "r")
            self.build_params = json.loads(params_in_file.read())
            params_in_file.close()
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

        try:
            params_out_file = open(
                os.path.join(self.directory, "build_params.json"), "w"
            )
            params_out_file.write(json.dumps(self.build_params, indent=2))
            params_out_file.close()
        except Exception as e:
            self.fail("Unable to write parameters to project folder.")

        return

    def manual_params_input(self):  # this is messy and can be better.
        """
        Requests the parameters in the required_params.json file,
        validates each parameter is the appropriate data type, creates
        the build_params dict object for the LabBuild object and
        writes the parameter file to the project directory.

        Attributes:
            None

        Returns:
            None
        """
        try:
            params_file = open("build_params.json", "r")
            self.build_params = json.loads(params_file.read())
            self.log(f"No parameters file provided, gathering user-provided input.")
        except Exception as e:
            self.fail(f"Default build parameters file build_params.json not found.")

        print(
            "Provide required information. Enter ? for help. Default values, when available, will be shown. To accept default value, press enter."
        )
        for (
            param,
            info,
        ) in (
            self.build_params.items()
        ):  # Iterate through the build options to gather info
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
            params_out_file = open(os.path.join(self.directory, "build_params.json"))
            params_out_file.write(json.dumps(self.build_params, indent=2))
            params_out_file.close()
        except Exception as e:
            self.fail(f"Unable to write parameters file to project directory: {e}")

    def read_project_data(self):
        # Read project output files
        self.log(f"Reading saved project data from {self.directory} folder.")
        try:
            build_params_file = open(
                os.path.join(self.directory, "build_params.json"), "r"
            )
            self.build_params = json.loads(build_params_file.read())
            build_params_file.close()
        except Exception as e:
            self.fail(f"Unable to read build params file: {e}")
        try:
            aws_params_file = open(os.path.join(self.directory, "aws_params.json"), "r")
            self.aws_params = json.loads(aws_params_file.read())
            aws_params_file.close()
        except Exception as e:
            self.fail(f"Unable to read AWS params file: {e}")
        try:
            aws_objects_file = open(
                os.path.join(self.directory, "aws_objects.json"), "r"
            )
            self.aws_objects = json.loads(aws_objects_file.read())
            aws_objects_file.close()
        except:
            self.fail(f"Unable to read AWS object data file: {e}")

        # update AWS params with current AWS secret data
        self.log("Updating AWS Parameters for template files.")
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

    def validate_info(self):  # this is messy and can be betters.
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

        self.aws_params["project"] = self.build_params["project"]["val"]
        self.log(f"Project name: {self.aws_params["project"]}")

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
            aws_params_out_file = open(
                os.path.join(self.directory, "aws_params.json"), "w"
            )
            aws_params_out_file.write(json.dumps(self.aws_params, indent=2))
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
            template_output = open(
                os.path.join(self.directory, folder, f"{template}.tf"), "w"
            )
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

    def cloud_tofu_project(self, action):
        match action:
            case "init":
                try:
                    self.log("Initializing OpenTofu Project for Cloud Networking.")
                    self.init = self.tofu.init()
                except Exception as e:
                    self.fail(f"Failed to initialize OpenTofu project: {e}")
            case "plan":
                try:
                    self.log("Planning OpenTofu Project for Cloud Networking")
                    self.plan_log, self.plan = self.tofu.plan()
                    if not self.plan or self.plan.errored:
                        self.fail(f"OpenTofu Plan Failed: {self.plan_log}")
                except Exception as e:
                    self.fail(f"Failed to run tofu plan: {e}")
            case "apply":
                try:
                    self.log("Applying OpenTofu Project for AWS Networking")
                    self.apply_log = self.tofu.apply()
                    self.log("OpenTofu Log:")
                    self.log(self.apply_log)
                    return True, self.apply_log
                except Exception as e:
                    self.fail(
                        f"OpenTofu plan failed to apply: {e}\nOpenTofu Apply Log:\n{self.apply_log}"
                    )
            case "get_aws_ids":
                self.log("Getting details of AWS Created Objects from tfstate file.")
                try:
                    tfstate_file = open(
                        os.path.join(self.directory, "cloud", "terraform.tfstate"), "r"
                    )
                    tfstate_json = json.load(tfstate_file)
                except Exception as e:
                    self.fail(
                        f"Unable to read {tfstate_file} from project cloud directory: {e}"
                    )

                for resource in tfstate_json["resources"]:
                    resource_name = resource["name"]
                    resource_id = resource["instances"][0]["attributes"]["id"]
                    self.log(f"{resource_name}: {resource_id}")
                    self.aws_objects[resource_name] = resource_id
                    if resource["type"] == "aws_lb":
                        self.aws_objects[f"{resource_name}_dns_name"] = resource["instances"][0][
                            "attributes"
                        ]["dns_name"]

                try:
                    aws_objects_out_file = open(
                        os.path.join(self.directory, "aws_objects.json"), "w"
                    )
                    aws_objects_out_file.write(json.dumps(self.aws_objects, indent=2))
                    aws_objects_out_file.close()
                    return
                except Exception as e:
                    self.fail(
                        f"Unable to write AWS created objects file to project directory: {e}"
                    )

    def cluster_tofu(self, cluster, action):
        match action:
            case "create":
                cluster.tofu_project = Tofu(cwd=cluster.tofu_path)
            case "init":
                try:
                    self.log(
                        f"Initializing OpenTofu Project for NC2 Cluster {cluster.name}"
                    )
                    cluster.init = cluster.tofu_project.init()
                except Exception as e:
                    self.fail(f"Failed to initialize OpenTofu project: {e}")
            case "plan":
                try:
                    self.log(
                        f"Planning OpenTofu Project for NC2 Cluster {cluster.name}"
                    )
                    cluster.plan_log, cluster.plan = cluster.tofu_project.plan()
                    if not cluster.plan or cluster.plan.errored:
                        self.fail(f"OpenTofu Plan Failed: {cluster.plan_log}")
                except Exception as e:
                    self.fail(f"Failed to run tofu plan: {e}")
            case "apply":
                try:
                    self.log(
                        f"Applying OpenTofu Project for NC2 Cluster {cluster.name}"
                    )
                    cluster.apply_log = cluster.tofu_project.apply()
                    self.log("OpenTofu Log:")
                    self.log(cluster.apply_log)
                    return True, cluster.apply_log
                except Exception as e:
                    self.fail(
                        f"OpenTofu plan failed to apply: {e}\nOpenTofu Apply Log:\n{cluster.apply_log}"
                    )

    def build_nc2_cluster_objects(
        self,
    ):  # As objects are built, we should check for an existing state file and use it. Saves time
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
                "cluster_fault_tolerance": {"factor": "1N/1D"},
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
            this_cluster.name = self.build_params["project"]["val"] + "-" + str(c)
            this_cluster.number = c
            self.log(f"NC2 Cluster {str(c)}: {this_cluster.name}")

            this_cluster.state_file = os.path.join(
                self.directory, "clusters", f"{c}.json"
            )
            self.log(f"Cluster State File: {this_cluster.state_file}")

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
            this_cluster.create_payload = deepcopy(self.nc2_cluster_base_payload)
            this_cluster.create_payload["data"]["name"] = (
                self.build_params["project"]["val"] + "-" + str(c)
            )
            this_cluster.create_payload["data"]["prism_central"][
                "management_subnet"
            ] = self.aws_objects["private_pc_subnet_" + str(c)]
            this_cluster.create_payload["data"]["network"]["fvn_config"][
                "subnet_cidr"
            ] = self.networks["flow_network_" + str(c)]
            this_cluster.create_payload["data"]["network"]["fvn_config"][
                "subnet_cloud_id"
            ] = self.aws_objects["private_flow_subnet_" + str(c)]
            self.log(
                f"Payload: \n{json.dumps(this_cluster.create_payload,indent=2)}\n#############\n",
                logonly=True,
            )
            self.nc2_clusters[c] = this_cluster

    def get_nc2_jwt(self):
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

    def create_nc2_clusters(self):
        self.log("Requesting NC2 Clusters via API.")
        for c, cluster in self.nc2_clusters.items():
            if os.path.exists(cluster.state_file):
                try:
                    cluster_state_file = open(cluster.state_file, "r")
                except Exception as e:
                    self.fail(
                        f"Cannot read cluster state file {cluster.state_file}: {e}"
                    )
                state_file_data = cluster_state_file.read()
                cluster_state_file.close()
                if len(state_file_data) > 0:
                    try:
                        state = json.loads(state_file_data)
                        if state["created"] == True:
                            self.log(
                                f"Cluster {c} - {cluster.name} already created, skipping."
                            )
                            cluster_state_file.close()
                            continue
                    except:
                        self.fail(
                            f"Cluster state file {cluster.state_file} exists with invalid data."
                        )
            else:
                self.log(f"Requesting cluster {cluster.number}: {cluster.name}")
                created, create_status_code, create_response = cluster.create_aws(
                    jwt=self.jwt_token
                )

                if created == True:
                    self.log(
                        f"Request successful. Response: \n{json.dumps(cluster.create_response,indent=2)}"
                    )
                    cluster_state_file = open(cluster.state_file, "w")
                    cluster_json = json.dumps(vars(cluster), indent=2)
                    cluster_state_file.write(cluster_json)
                    cluster_state_file.close()
                else:
                    self.fail(
                        f"Cluster creation failed with status code {create_status_code}, response:\n{json.dumps(create_response,indent=2)}"
                    )

    def read_built_cluster_data(self):
        self.nc2_clusters = {}
        for c in range(0, self.build_params["cluster_count"]["val"]):
            this_cluster = nc2Cluster()
            try:  # Read cluster state file
                cluster_state_file = open(
                    os.path.join(self.directory, "clusters", f"{c}.json")
                )
                cluster_state = json.loads(cluster_state_file.read())
                cluster_state_file.close()
            except Exception as e:
                self.fail(f"Unable to load cluster state for cluster {c}: {e}")
            for (
                k,
                v,
            ) in (
                cluster_state.items()
            ):  # Load data from cluster state file into cluster object
                this_cluster.__dict__[k] = v
            this_cluster.project = self.build_params["project"][
                "val"
            ]  # Update the project value
            if (
                this_cluster.cluster_id == None
            ):  # If a cluster ID isn't set for the cluster, get the cluster ID and the current cluster info.
                this_cluster.get_cluster_id(
                    self.jwt_token
                )  # Get the cluster ID based on the cluster name
                this_cluster.get_cluster(
                    self.jwt_token
                )  # Get the cluster details now that we have the cluster ID
                cluster_state_file = open(
                    os.path.join(self.directory, "clusters", f"{c}.json"), "w"
                )  # refresh the cluster state file with the new state
                cluster_state_file.write(json.dumps(this_cluster.__dict__, indent=2))
                cluster_state_file.close()
            self.nc2_clusters[c] = (
                this_cluster  # add the cluster object to the list of clusters
            )
        return

    def generate_aws_nlb_config(self):

        try:
            nlb_template_file = open(os.path.join("templates", "aws_nlb.tf.j2"), "r")
            nlb_template = Template(nlb_template_file.read())
            nlb_template_file.close()
        except Exception as e:
            self.fail(f"Error loading AWS NLB Template file: {e}.")

        nlb_template_output = open(
            os.path.join(self.directory, "cloud", "aws_nlb.tf"), "w"
        )

        for c, cluster in self.nc2_clusters.items():
            nlb_template_output.write(nlb_template.render(cluster.__dict__))

        nlb_template_output.close()
        return

    def get_cluster_access_url(self):
        for c, cluster in self.nc2_clusters.items():
            cluster.lb_dns_name = self.aws_objects[f'{cluster.name}-nlb_dns_name']
            cluster.lb_port = 9440
            cluster.access_url = f"https://{cluster.lb_dns_name}:{str(cluster.lb_port)}"
            print(f"Cluster {cluster.number} - {cluster.name} - URL: {cluster.access_url}")
            cluster.write_state_file()

    def load_cluster_images(self):
        for c, cluster in self.nc2_clusters.items():
            try:
                cluster.tofu_folder = os.path.join("clusters", str(cluster.number))
                os.mkdir(os.path.join(self.directory, cluster.tofu_folder))
                self.log(f"'{cluster.tofu_folder}' directory created successfully.")
            except FileExistsError:
                self.log(f"Directory '{cluster.tofu_folder}' already exists.")
            except PermissionError:
                self.log(
                    f"Permission denied: Unable to create '{cluster.tofu_folder}'."
                )
            except Exception as e:
                self.fail(f"An error occurred: {e}")
                quit()
            try:
                self.render_template(
                    folder=cluster.tofu_folder,
                    template="pc_provider",
                    values=cluster.__dict__,
                )
                self.render_template(
                    folder=cluster.tofu_folder,
                    template="pc_images",
                    values=VM_IMAGE_FILES,
                )
            except Exception as e:
                self.fail(f"Unable to create Prism Central TF files: {e}")
            cluster.tofu_path = Path(os.path.join(self.directory, cluster.tofu_folder))
            self.cluster_tofu(cluster=cluster, action="create")
            self.cluster_tofu(cluster=cluster, action="init")
            self.cluster_tofu(cluster=cluster, action="plan")
            self.cluster_tofu(cluster=cluster, action="apply")
        pass

    def fns_labs_prep(self):
        '''
        This function prepares the clusters with a VPC and VMs for 
        Flow Network Security Training Labs. 
        
        A VPC called FNS-Lab-VPC will be created and attached to the transit VPC via overlay-external-subnet-nat,
        and assigned the .254 address from the NAT subnet as the Router IP. A single subnet called "FNS-VMs" will
        be created in the VPC with a subnet of 100.64.128.0/24.
        
        A small WordPress environment will be created containing three VMs:
        - FNS-WEB01 - 100.64.128.10
        - FNS-WEB02 - 100.64.128.11
        - FNS-DB01  - 100.64.128.25

        All three VMs will have default credentials of U: ubuntu | P: Nutanix.123

        The Web Servers will be pre-configured via cloud-init using the web_vm_config.j2 template.
        This template will install Apache & PHP and download and pre-configure WordPress to point to a 
        database on the DB server.
        The DB server will be pre-configured via cloud-init using the db_vm_config.j2 template.
        This template will install mariaDB and configure it with the database of an already-installed
        WordPress site with a single demo page. The database password will be Nutanix.123
        '''
        for c,cluster in self.nc2_clusters.items():
            do_it = input(f"Apply FNS Lab config to cluster {cluster.name}? ")
            if do_it != "y":
                continue
            try:
                cluster.tofu_folder = os.path.join("clusters", str(cluster.number))
                os.mkdir(os.path.join(self.directory, cluster.tofu_folder))
                self.log(f"'{cluster.tofu_folder}' directory created successfully.")
            except FileExistsError:
                self.log(f"Directory '{cluster.tofu_folder}' already exists.")
            except PermissionError:
                self.log(
                    f"Permission denied: Unable to create '{cluster.tofu_folder}'."
                )
            except Exception as e:
                self.fail(f"An error occurred: {e}")
                quit()
            try:
                self.render_template(
                    folder=cluster.tofu_folder,
                    template="pc_provider",
                    values=cluster.__dict__,
                )
                self.render_template(
                    folder=cluster.tofu_folder,
                    template="pc_images",
                    values=VM_IMAGE_FILES,
                )
            except Exception as e:
                self.fail(f"Unable to create Prism Central TF files: {e}")
            ###
            # Networking
            ###
            # generate the networking terraform
            vpc_config = { "flow_subnet_cidr": cluster.flow_subnet_cidr }
            self.render_template(
                folder=cluster.tofu_folder,
                template="fns_lab_vpcs",
                values=vpc_config,
            )
            ###
            # WEB-01
            ###
            web01_cloud_init = open(os.path.join("cloud_init","fns-web01.yaml")).read()
            web01_ci_bytes = web01_cloud_init.encode('utf-8')
            web01_b64 = base64.b64encode(web01_ci_bytes).decode('utf-8')
            web01 = {
                "name": "FNS-WEB01",
                "vm_password": "Nutanix.123",
                "description": "FNS Lab Web Server 1",
                "image": "ubuntu-24_04_noble-numbat",
                "ip_address": "100.64.128.10",
                "cloud_init": web01_b64,
            }
            self.render_template(
                folder=cluster.tofu_folder,
                template="fns_lab_web01",
                values=web01,
            )
            ####
            # WEB-02
            ###
            web02_cloud_init = open(os.path.join("cloud_init","fns-web02.yaml")).read()
            web02_ci_bytes = web02_cloud_init.encode('utf-8')
            web02_b64 = base64.b64encode(web02_ci_bytes).decode('utf-8')
            web02 = {
                "name": "FNS-WEB02",
                "vm_password": "Nutanix.123",
                "description": "FNS Lab Web Server 2",
                "image": "ubuntu-24_04_noble-numbat",
                "ip_address": "100.64.128.11",
                "cloud_init": web02_b64,
            }
            self.render_template(
                folder=cluster.tofu_folder,
                template="fns_lab_web02",
                values=web02,
            )
            cluster.tofu_path = Path(os.path.join(self.directory, cluster.tofu_folder))
            self.cluster_tofu(cluster=cluster, action="create")
            self.cluster_tofu(cluster=cluster, action="init")
            self.cluster_tofu(cluster=cluster, action="plan")
            self.cluster_tofu(cluster=cluster, action="apply")


    def close_logfile(self):
        self.logfile.close()
